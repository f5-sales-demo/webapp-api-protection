"""Synthetic verifier checks; not live security acceptance proof."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tests import demo_verify_fixtures as fixtures
from tests.demo_test_support import ensure, ensure_equal, expect_error

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import demo_verify as v
import demo_verify_client as transport
import demo_verify_evidence as evaluation
import demo_verify_scope as scope
import demo_verify_types as contracts

USER = fixtures.USER
DOMAINS = fixtures.DOMAINS


class AcceptanceReadinessTests(unittest.TestCase):
    def test_first_of_seven_hard_scheduled_failures_ends_polling_immediately(self):
        for error in (
            "configuration",
            "tool_missing",
            "metrics_unavailable",
            "metrics_failed",
            "SECRET",
        ):
            history = [
                {
                    "run_id": format(i, "032x"),
                    "started_epoch": 101 + i * 300,
                    "trigger": "scheduled",
                    "status": "failed",
                    "error_class": error,
                    "failures": ["SECRET"],
                }
                for i in range(7)
            ]
            client = fixtures.client()
            client.deadline = time.monotonic() + 2400
            client.ssh = Mock(
                return_value=json.dumps({"timer_active": False, "history": history})
            )
            client.pages = Mock()
            out = {
                "namespace": "demo",
                "loadbalancer_name": "demo-lb",
                "domains": DOMAINS,
                "generator": {},
            }
            with (
                self.subTest(error=error),
                patch.object(scope, "effective"),
                patch.object(
                    v, "probes", return_value=(USER, [fixtures.probe("mud")], [])
                ),
                patch.object(v.time, "time", return_value=100),
                patch.object(v.time, "sleep") as sleep,
            ):
                code, report = v.acceptance(client, out, Mock(poll_seconds=10))
            ensure_equal(code, contracts.FAILURE)
            ensure_equal(report["traffic_failure"]["run_id"], "0" * 32)
            ensure(not report["scheduled_traffic"])
            ensure("SECRET" not in json.dumps(report))
            client.ssh.assert_called_once()
            client.pages.assert_not_called()
            sleep.assert_not_called()

    def test_report_redaction_and_missing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with patch.dict(
                os.environ, {"XCSH_API_URL": "", "XCSH_API_TOKEN": "SECRET"}
            ):
                code = v.main(
                    [
                        "--outputs-json",
                        "/missing",
                        "--phase",
                        "readiness",
                        "--report",
                        str(path),
                    ]
                )
            ensure_equal(code, contracts.FAILURE)
            text = path.read_text()
            ensure("SECRET" not in text)
            ensure(not json.loads(text)["verified"])
            ensure_equal(path.stat().st_mode & 0o777, 0o600)

    def test_mitigation_without_documented_detection_remains_pending(self):
        client = fixtures.client()
        client.deadline = time.monotonic() + 0.001
        event = fixtures.event()
        event.update(
            sec_event_type="api_sec_event",
            policy_hits={
                "policy_hits": [
                    {"malicious_user_mitigate_action": "MUM_BLOCK_TEMPORARILY"}
                ]
            },
        )
        # Plausible but undocumented log fields MUST NOT become security proof.
        client.pages = Mock(
            side_effect=[
                [event],
                [
                    {
                        "namespace": "demo",
                        "vh_name": "demo-lb",
                        "user": USER,
                        "threat_level": "HIGH",
                        "first_event_time": 100,
                        "last_event_time": 101,
                        "detected_actions": ["block_temporarily"],
                    }
                ],
            ]
        )
        client.ssh = Mock(return_value=json.dumps({}))
        out = {
            "namespace": "demo",
            "loadbalancer_name": "demo-lb",
            "domains": DOMAINS,
            "generator": {},
        }
        with (
            patch.object(scope, "effective"),
            patch.object(v, "probes", return_value=(USER, [fixtures.probe("mud")], [])),
            patch.object(evaluation, "continuous_traffic_ready", return_value=True),
        ):
            client.ssh.return_value = json.dumps({"history": []})
            code, report = v.acceptance(client, out, Mock(poll_seconds=1))
        ensure_equal(code, contracts.PENDING)
        ensure(not report["mud_mitigation"])
        ensure(not report["mud_detection"])
        ensure_equal(report["suspicious_log_count"], 1)
        ensure("mud_detection" in report["pending"])

    def test_opaque_mud_detection_always_pending(self):
        client = fixtures.client()
        client.deadline = time.monotonic() + 0.001
        client.pages = Mock(return_value=[fixtures.event()])
        client.ssh = Mock(
            return_value=json.dumps({"timer_active": False, "history": []})
        )
        args = Mock(poll_seconds=1)
        out = {
            "namespace": "demo",
            "loadbalancer_name": "demo-lb",
            "domains": DOMAINS,
            "generator": {},
        }
        with (
            patch.object(scope, "effective"),
            patch.object(v, "probes", return_value=(USER, [fixtures.probe("mud")], [])),
        ):
            code, report = v.acceptance(client, out, args)
        ensure_equal(code, contracts.PENDING)
        ensure(not report["mud_detection"])

    def test_mud_propagation_pending_then_blocked_with_good_control(self):
        client = Mock()
        client.request.side_effect = [(200, {}), (200, {}), (403, {}), (200, {})]
        probe = fixtures.mud_evidence()[1]
        with patch.object(v.time, "time", side_effect=[103, 104]):
            ensure(not v.mitigation_probe(client, probe))
            ensure(bool(v.mitigation_probe(client, probe)))
        ensure_equal(probe["mitigation_sent_at"], 103)
        ensure_equal(client.request.call_args.args[3], probe["user"] + "-negative")

    def test_mud_propagation_fails_if_independent_user_blocked(self):
        client = Mock()
        client.request.side_effect = [(403, {}), (403, {})]
        with expect_error(contracts.EvidenceError):
            v.mitigation_probe(client, fixtures.mud_evidence()[1])

    def test_two_measurements_without_fresh_control_attribution_cannot_pass(self):
        status, since = fixtures.runs()
        raw, mud, waf = fixtures.mud_evidence()
        mud.update(mitigation_sent_at=104, mitigation_blocked=True)
        required = [mud] + [
            dict(fixtures.probe("rate-limit"), host=domain) for domain in DOMAINS
        ]
        client = Mock(deadline=time.monotonic())
        client.ssh.return_value = json.dumps(fixtures.continuous_status(status))
        client.pages.side_effect = lambda *args: (
            [raw]
            if len(args) > 4 and args[4]
            else [waf, fixtures.mud_fixture()["mitigation_event"]]
        )
        out = {
            "namespace": "demo",
            "loadbalancer_name": "demo-lb",
            "domains": DOMAINS,
            "generator": {},
        }
        now = time.time()
        with (
            patch.object(scope, "effective"),
            patch.object(v, "probes", return_value=(USER, required, [])),
            patch.object(v.time, "time", side_effect=[since, now, now, now]),
        ):
            code, report = v.acceptance(client, out, Mock(poll_seconds=1))
        ensure_equal(code, contracts.PENDING)
        ensure(bool(report["scheduled_traffic"]))
        ensure(not report["controls_attributed"])
        ensure(bool(report["mud_detection"]))
        ensure(bool(report["mud_mitigation"]))
        ensure_equal(len(report["continuous_catalog"]), 2)
        ensure(
            bool(
                all(
                    not outcome["rate_denial_observed"]
                    for run in report["traffic_runs"]
                    for outcome in run["rate_outcomes"].values()
                )
            )
        )

    def test_complete_fresh_mud_acceptance_after_delayed_poll(self):
        raw, probe, waf = fixtures.mud_evidence()
        mitigation = fixtures.mud_fixture()["mitigation_event"]
        other = fixtures.probe()
        events = [waf, fixtures.event(), mitigation]
        client = Mock(deadline=time.monotonic() + 100)
        client.pages.side_effect = lambda *args: (
            [raw] if len(args) > 4 and args[4] else events
        )
        client.request.side_effect = [(200, {}), (200, {}), (403, {}), (200, {})]
        client.ssh.return_value = json.dumps({"history": []})
        out = {
            "namespace": "demo",
            "loadbalancer_name": "demo-lb",
            "domains": DOMAINS,
            "generator": {},
        }
        # RFC3339 MUM event at 105 must be queried after its probe time.
        with (
            patch.object(scope, "effective"),
            patch.object(v, "probes", return_value=(USER, [probe, other], [])),
            patch.object(evaluation, "continuous_traffic_ready", return_value=True),
            patch.object(v.time, "sleep"),
            patch.object(v.time, "time", side_effect=[100, 104, 104, 106, 106, 107]),
        ):
            code, report = v.acceptance(client, out, Mock(poll_seconds=1))
        ensure_equal(code, contracts.VERIFIED)
        ensure(bool(report["mud_detection"]))
        ensure(bool(report["mud_mitigation"]))
        ensure_equal(client.request.call_count, 4)

    def test_final_acceptance_report_resolves_only_complete_fresh_evidence(self):
        for scenario in ("success", "missing-controls", "timeout", "failed-schedule"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                status, since = fixtures.runs()
                raw, mud, waf = fixtures.mud_evidence()
                mud.update(mitigation_sent_at=104, mitigation_blocked=True)
                events = [
                    waf,
                    fixtures.event(),
                    fixtures.mud_fixture()["mitigation_event"],
                ]
                required = [mud, fixtures.probe()]
                if scenario == "missing-controls":
                    required.append(fixtures.probe("unknown"))
                if scenario == "timeout":
                    status = {"history": []}
                elif scenario == "failed-schedule":
                    status["history"][-1].update(
                        status="failed", error_class="metrics_failed"
                    )
                client = Mock(deadline=100, read_retries=[])
                client.ssh.side_effect = [
                    json.dumps({"history": []}),
                    json.dumps({"history": []}),
                    json.dumps(fixtures.continuous_status(status)),
                    json.dumps(fixtures.continuous_status(status)),
                ]
                client.pages.side_effect = lambda *args, raw=raw, events=events: (
                    [raw] if len(args) > 4 and args[4] else events
                )
                out = {
                    "namespace": "demo",
                    "loadbalancer_name": "demo-lb",
                    "domains": DOMAINS,
                    "generator": {},
                }
                path = Path(tmp) / "report.json"
                clock = (iter([since]), time.time())
                with (
                    patch.object(transport, "Client", return_value=client),
                    patch.object(scope, "outputs", return_value=out),
                    patch.object(scope, "effective"),
                    patch.object(
                        v,
                        "probes",
                        return_value=(
                            USER,
                            required,
                            [
                                {
                                    "control": "waf",
                                    "status": 403,
                                    "path": "/httpbin/get",
                                }
                                for _ in range(3)
                            ],
                        ),
                    ),
                    patch.object(
                        v.time,
                        "time",
                        side_effect=lambda clock=clock: next(clock[0], clock[1]),
                    ),
                    patch.object(v.time, "monotonic", side_effect=[0, 0, 100]),
                    patch.object(v.time, "sleep") as sleep,
                    patch("builtins.print"),
                ):
                    code = v.main(
                        [
                            "--outputs-json",
                            "synthetic",
                            "--phase",
                            "acceptance",
                            "--poll-seconds",
                            "1",
                            "--report",
                            str(path),
                        ]
                    )
                report = json.loads(path.read_text())
                evidence = report["evidence"]
                sleep.assert_called_once_with(1)
                ensure_equal(report["exit_code"], code)
                ensure_equal(report["verified"], scenario == "success")
                if scenario == "success":
                    ensure_equal(code, contracts.VERIFIED)
                    ensure("pending" not in evidence)
                    ensure("failure" not in evidence)
                    ensure("awaiting fresh evidence" not in path.read_text())
                    for gate in (
                        "controls_attributed",
                        "scheduled_traffic",
                        "mud_detection",
                        "mud_mitigation",
                    ):
                        ensure(bool(evidence[gate]))
                    ensure_equal(len(evidence["continuous_catalog"]), 2)
                    ensure_equal(evidence["probe_count"], 3)
                    ensure(evidence["suspicious_log_count"] > 0)
                    ensure(
                        bool(
                            all(
                                not outcome["rate_denial_observed"]
                                for run in evidence["traffic_runs"]
                                for outcome in run["rate_outcomes"].values()
                            )
                        )
                    )
                elif scenario == "failed-schedule":
                    ensure_equal(code, contracts.FAILURE)
                    ensure_equal(evidence["failure"], "fresh scheduled traffic failed")
                    ensure("pending" in evidence)
                    ensure("traffic_failure" in evidence)
                else:
                    ensure_equal(code, contracts.PENDING)
                    missing = (
                        "controls_attributed"
                        if scenario == "missing-controls"
                        else "scheduled_traffic"
                    )
                    ensure(missing in evidence["pending"])
                    ensure_equal(
                        evidence["scheduled_traffic"], scenario == "missing-controls"
                    )

    def test_azure_retry_diagnostics_report_success_and_failure(self):
        sub = "11111111-1111-1111-1111-111111111111"
        rid = f"/subscriptions/{sub}/resourceGroups/demo"
        for succeeds in (True, False):
            with self.subTest(succeeds=succeeds), tempfile.TemporaryDirectory() as tmp:
                client = fixtures.client()
                client.deadline = time.monotonic() + 60
                result = Mock(
                    returncode=1,
                    stdout=b"",
                    stderr=b'INFO: Response status: 404\nERROR: {"error":{"code":"ResourceNotFound","message":"SECRET"}}',
                )
                attempts = [transport.subprocess.TimeoutExpired("SECRET", 20)]
                attempts.append(
                    result
                    if succeeds
                    else transport.subprocess.TimeoutExpired("SECRET", 20)
                )
                report_path = Path(tmp) / "report.json"
                with (
                    patch.object(transport, "Client", return_value=client),
                    patch.object(
                        scope,
                        "absence",
                        side_effect=lambda c, _manifest: (
                            not c.azure_exists(sub, rid, "2021-04-01")
                        ),
                    ),
                    patch.object(Path, "read_text", return_value="{}"),
                    patch.object(transport.subprocess, "run", side_effect=attempts),
                    patch.object(v.time, "sleep"),
                    patch("builtins.print"),
                ):
                    code = v.main(
                        [
                            "--outputs-json",
                            "unused",
                            "--phase",
                            "absence",
                            "--run-manifest",
                            "unused",
                            "--report",
                            str(report_path),
                        ]
                    )
                report_text = report_path.read_text()
                report = json.loads(report_text)
                ensure_equal(
                    code, contracts.VERIFIED if succeeds else contracts.FAILURE
                )
                ensure_equal(report["verified"], succeeds)
                ensure_equal(
                    report["read_retries"], [{"reason": "timeout", "attempt": 1}]
                )
                ensure("SECRET" not in report_text)
                ensure(rid not in report_text)

    def test_readiness_actual_rewritten_url_and_cloud_done(self):
        out = {"domains": DOMAINS, "origin": {}, "generator": {}}
        with patch.object(scope, "effective"):
            result = v.readiness(fixtures.readiness_client(), out, Mock())
            ensure_equal(result["application_domains"], 2)
            for status in ("done (degraded)", "error", "disabled"):
                with expect_error(contracts.EvidenceError):
                    v.readiness(fixtures.readiness_client(status), out, Mock())
            for host, path in (
                ("other.example.test", "/get"),
                (None, "/httpbin/get"),
                (None, "/get?x=/get"),
            ):
                with expect_error(contracts.EvidenceError):
                    v.readiness(
                        fixtures.readiness_client(
                            returned_host=host, returned_path=path
                        ),
                        out,
                        Mock(),
                    )

    def test_readiness_poll_exceeds_short_budget_then_done(self):
        client = fixtures.readiness_client()
        done = json.dumps({"status": "done", "errors": [], "recoverable_errors": {}})
        running = json.dumps({"status": "running", "errors": []})
        client.ssh.side_effect = [
            running,
            running,
            running,
            done,
            "Result=success\nExecMainStatus=0\n",
            done,
            "Result=success\nExecMainStatus=0\n",
            json.dumps(
                {
                    "ready": True,
                    "schema_version": 1,
                    "checks": [{"name": "replica", "ready": True}],
                }
            ),
            json.dumps({"ready": True}),
        ]
        clock = [0]
        real = fixtures.client()
        real.deadline = 60
        client.remaining.side_effect = real.remaining
        args = Mock(poll_seconds=10)
        with (
            patch.object(scope, "effective"),
            patch.object(v.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                v.time,
                "sleep",
                side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
            ),
        ):
            ensure_equal(
                v.readiness(
                    client, {"domains": DOMAINS, "origin": {}, "generator": {}}, args
                )["origin_checks"],
                1,
            )
        ensure_equal(clock[0], 30)
        ensure("--wait" not in client.ssh.call_args_list[0].args[2])

    def test_cloud_init_deadline_and_ssh_fail_fast(self):
        out = {"domains": DOMAINS, "origin": {}, "generator": {}}
        for failure in (
            contracts.EvidenceError("required command failed"),
            contracts.EvidenceError("deadline exceeded"),
        ):
            client = fixtures.readiness_client()
            client.ssh.side_effect = failure
            with (
                patch.object(scope, "effective"),
                expect_error(contracts.EvidenceError),
            ):
                v.readiness(client, out, Mock(poll_seconds=10))
            ensure_equal(client.ssh.call_count, 1)
            client.request.assert_not_called()

    def test_cloud_init_running_deadline_expires(self):
        client = fixtures.readiness_client()
        client.ssh.side_effect = None
        client.ssh.return_value = json.dumps({"status": "running"})
        clock = [0]
        real = fixtures.client()
        real.deadline = 25
        client.remaining.side_effect = real.remaining
        with (
            patch.object(scope, "effective"),
            patch.object(v.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(
                v.time,
                "sleep",
                side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
            ),
            expect_error(contracts.EvidenceError, "deadline exceeded"),
        ):
            v.readiness(
                client,
                {"domains": DOMAINS, "origin": {}, "generator": {}},
                Mock(poll_seconds=10),
            )
        ensure_equal(clock[0], 25)
        client.request.assert_not_called()

    def test_cloud_init_degraded_and_stage_errors_fail(self):
        for report in (
            {"status": "done", "extended_status": "degraded done"},
            {"status": "done", "modules-final": {"errors": ["SECRET"]}},
            {"status": "done", "recoverable_errors": {"WARNING": ["SECRET"]}},
        ):
            client = fixtures.readiness_client()
            client.ssh.side_effect = [json.dumps(report)]
            with (
                patch.object(scope, "effective"),
                expect_error(contracts.EvidenceError) as error,
            ):
                v.readiness(
                    client, {"domains": DOMAINS, "origin": {}, "generator": {}}, Mock()
                )
            ensure("SECRET" not in str(error.exception))
            client.request.assert_not_called()

    def test_cloud_init_running_warning_then_terminal_and_unit_success(self):
        client = fixtures.readiness_client()
        client.remaining.return_value = 30
        tail = list(client.ssh.side_effect)[2:]
        running = fixtures.azure_retry_status()
        running.update(status="running", extended_status="degraded running")
        running["modules-final"]["finished"] = None
        client.ssh.side_effect = [
            json.dumps(running),
            json.dumps(fixtures.azure_retry_status()),
            "Result=success\nExecMainStatus=0\n",
            *tail,
        ]
        with patch.object(scope, "effective"), patch.object(v.time, "sleep"):
            report = v.readiness(
                client,
                {"domains": DOMAINS, "origin": {}, "generator": {}},
                Mock(poll_seconds=1),
            )
        ensure(bool(report["cloud_init"]))
        ensure_equal(report["cloud_init_info"]["origin"]["warnings_accepted"], 4)
        ensure_equal(report["cloud_init_info"]["generator"]["warnings_accepted"], 0)

    def test_cloud_init_completion_requires_successful_final_unit(self):
        for status in (
            fixtures.azure_retry_status(),
            {"status": "done", "errors": [], "recoverable_errors": {}},
        ):
            client = fixtures.readiness_client()
            client.ssh.side_effect = [
                json.dumps(status),
                "Result=exit-code\nExecMainStatus=1\n",
            ]
            with (
                patch.object(scope, "effective"),
                expect_error(contracts.EvidenceError),
            ):
                v.readiness(
                    client, {"domains": DOMAINS, "origin": {}, "generator": {}}, Mock()
                )
            client.request.assert_not_called()

    def test_cloud_init_pending_warnings_timeout_and_fatal_running(self):
        client = fixtures.readiness_client()
        running = fixtures.azure_retry_status()
        running.update(status="running", extended_status="degraded running")
        client.ssh.side_effect = [json.dumps(running)]
        client.remaining.side_effect = [1, contracts.EvidenceError("deadline exceeded")]
        with (
            patch.object(scope, "effective"),
            expect_error(contracts.EvidenceError, "deadline"),
        ):
            v.readiness(
                client, {"domains": DOMAINS, "origin": {}, "generator": {}}, Mock()
            )
        running["modules-final"]["errors"] = ["fatal"]
        with expect_error(contracts.EvidenceError):
            evaluation.cloud_init_state(running)
        for status in ("unknown", "disabled", "error"):
            with expect_error(contracts.EvidenceError):
                evaluation.cloud_init_state({"status": status})

    def test_readiness_rejects_generator_cloud_init_failure(self):
        client = fixtures.readiness_client()
        client.ssh.side_effect = [
            json.dumps({"status": "done", "errors": [], "recoverable_errors": {}}),
            "Result=success\nExecMainStatus=0\n",
            json.dumps({"status": "error", "errors": ["install failed"]}),
        ]
        out = {"domains": DOMAINS, "origin": {}, "generator": {}}
        with patch.object(scope, "effective"), expect_error(contracts.EvidenceError):
            v.readiness(client, out, Mock())
        client.request.assert_not_called()

    def test_rate_burst_observed_late_denial_and_refill(self):
        for statuses in (
            [200] * 23 + [429] * 7,
            [200] * 22 + [429] * 8,
            [200] * 21 + [429] * 8 + [200],
        ):
            client = fixtures.rate_client([*statuses, 200, 200])
            deadline = client.deadline
            probe, summary = v.rate_burst(client, DOMAINS[0], USER)
            ensure_equal(client.deadline, deadline)
            ensure_equal(summary["request_count"], 30)
            ensure_equal(summary["status_counts"]["429"], statuses.count(429))
            ensure_equal(summary["status_counts"]["200"], statuses.count(200))
            ensure_equal(summary["first_denial_request"], statuses.index(429) + 1)
            ensure_equal(summary["threshold"], 20)
            ensure_equal(summary["unit"], "MINUTE")
            ensure_equal(summary["bucket_semantics_source"], v.RATE_BUCKET_SOURCE)
            ensure_equal(len(probe["denial_requests"]), statuses.count(429))
            ensure_equal(probe["sent_at"], probe["denial_requests"][0]["sent_at"])
            ensure(summary["duration_seconds"] <= 30)
            ensure_equal(client.request.call_count, 32)
            ensure_equal(
                client.request.call_args_list[-2].args[3], USER + "-independent"
            )
            ensure_equal(
                client.request.call_args_list[-1].args[1:],
                ("/httpbin/get", "GET", USER),
            )
            ensure(bool(summary["independent_user_allowed"]))
            ensure(bool(summary["same_user_unrelated_path_allowed"]))


class BoundedProbeTests(unittest.TestCase):
    def test_rate_burst_all_200_is_diagnostic_failure(self):
        client = fixtures.rate_client([200] * 30)
        with expect_error(contracts.EvidenceError, "no HTTP 429") as caught:
            v.rate_burst(client, DOMAINS[0], USER)
        summary = json.loads(str(caught.exception).split(": ", 1)[1])
        ensure_equal(summary["status_counts"], {"200": 30})
        ensure_equal(summary["request_count"], 30)
        ensure("duration_seconds" in summary)
        ensure_equal(client.request.call_count, 30)

    def test_rate_burst_wrong_denial_and_origin_pages_fail(self):
        for code, body in (
            (403, None),
            (503, None),
            (200, None),
            (200, {"url": "http://other.example.test/anything/rate-limit"}),
            (200, {"url": "http://" + DOMAINS[0] + "/get"}),
        ):
            client = fixtures.rate_client([200] * 30)
            client.request.side_effect = None
            client.request.return_value = (code, body)
            with expect_error(contracts.EvidenceError):
                v.rate_burst(client, DOMAINS[0], USER)
        for code in (403, 503):
            client = fixtures.rate_client([200] * 21 + [code])
            with expect_error(contracts.EvidenceError, "only HTTP 429"):
                v.rate_burst(client, DOMAINS[0], USER)

    def test_rate_burst_isolation_controls_must_reach_origin(self):
        for controls in ([403, 200], [200, 429]):
            client = fixtures.rate_client([200] * 22 + [429] * 8 + controls)
            with expect_error(contracts.EvidenceError, "positive origin"):
                v.rate_burst(client, DOMAINS[0], USER)

    def test_rate_burst_deadline_and_transport_bound(self):
        client = fixtures.rate_client([200] * 30)
        client.deadline = 102
        with (
            patch.object(v.time, "monotonic", side_effect=[100, 100, 102, 102]),
            expect_error(contracts.EvidenceError, "duration budget exhausted"),
        ):
            v.rate_burst(client, DOMAINS[0], USER)
        ensure_equal(client.request.call_count, 1)
        ensure_equal(client.deadline, 102)
        client = fixtures.rate_client([200] * 30)
        client.request.side_effect = contracts.EvidenceError(
            "application transport failure"
        )
        deadline = client.deadline
        with expect_error(
            contracts.EvidenceError, "application transport failure"
        ) as caught:
            v.rate_burst(client, DOMAINS[0], USER)
        ensure('"request_count": 0' in str(caught.exception))
        ensure_equal(client.deadline, deadline)

    def test_paired_probes_use_separate_fresh_rate_users_and_late_denials(self):
        client = Mock(deadline=time.monotonic() + 100)
        counts: dict[str, int] = {}

        def respond(host, path, method, user, body=None):
            code = 200
            if path == "/httpbin/anything/rate-limit" and user.endswith("-rate"):
                counts[user] = counts.get(user, 0) + 1
                allowed = 23 if host == DOMAINS[0] else 22
                code = 200 if counts[user] <= allowed else 429
            elif (
                (host in DOMAINS and path == "/httpbin/anything/admin")
                or user.endswith(("-missing", "-wrong", "-waf"))
                or (user.endswith("-mud") and "?" in path)
            ):
                code = 403
            return code, {
                "url": "http://" + host + path.removeprefix("/httpbin"),
                "headers": {"X-Mud-User": user},
            }

        client.request.side_effect = respond
        run, required, results = v.probes(
            client,
            {
                "domains": DOMAINS,
                "origin": {"public_ip": "192.0.2.1"},
            },
        )
        rate_probes = [p for p in required if p["control"] == "rate-limit"]
        bursts = [r for r in results if r["control"] == "rate-burst"]
        ensure_equal(
            [p["user"] for p in rate_probes], [run + "-d0-rate", run + "-d1-rate"]
        )
        ensure_equal(
            [r["status_counts"] for r in bursts],
            [{"200": 23, "429": 7}, {"200": 22, "429": 8}],
        )
        ensure_equal(client.request.call_count, 148)
