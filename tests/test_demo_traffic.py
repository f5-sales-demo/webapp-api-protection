"""Deterministic bookkeeping and failure tests, never live security acceptance."""

import base64
import copy
import json
import os
import subprocess
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from typing import Any
from unittest import mock

from tests.demo_test_support import ensure, ensure_equal, expect_error
from tests.demo_traffic_fixtures import (
    DOMAINS,
    VEGETA_VERSION,
    FakeTool,
    authorize,
    configuration,
    records,
    report,
    status,
    traffic,
)


class ConfigurationTests(unittest.TestCase):
    def test_invalid_complete_profile_never_authorizes_starts_or_calls_network(self):
        cases: list[tuple[str, Any]] = [
            ("mud_bad_traffic", False),
            ("mud_bad_traffic", "true"),
            ("target_domains", DOMAINS[:1]),
            ("target_domains", DOMAINS * 2),
            ("target_domains", [DOMAINS[0], "api.example.com/SECRET"]),
            ("target_domains", [DOMAINS[0], "-bad.example.com"]),
            ("target_domains", [DOMAINS[0], None]),
            ("target_origin_ip", "127.0.0.1"),
            ("target_origin_ip", "SECRET"),
            ("tool_tier", "unknown"),
            ("rate", 100),
        ]
        for key, value in cases:
            bad = {**configuration(), key: value}
            with (
                self.subTest(key=key),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(traffic, "ROOT", Path(directory)),
                mock.patch.object(traffic, "config", return_value=bad),
                mock.patch.object(traffic.subprocess, "run") as run,
                mock.patch.object(traffic.urllib.request, "build_opener") as network,
                mock.patch.object(traffic.sys, "argv", ["tgen-control", "start"]),
            ):
                with expect_error(traffic.ConfigurationError) as error:
                    traffic.main()
                ensure("SECRET" not in str(error.exception))
                run.assert_not_called()
                network.assert_not_called()
                ensure(not (Path(directory) / "authorization.json").exists())

    def test_prestart_exercises_canonical_targets_before_tools(self):
        with (
            mock.patch.object(
                traffic, "targets", side_effect=ValueError("SECRET")
            ) as targets,
            mock.patch.object(traffic.subprocess, "run") as run,
        ):
            with expect_error(traffic.ConfigurationError, "^invalid_configuration$"):
                traffic.cheap_ready(configuration())
            targets.assert_called_once_with(DOMAINS, "configuration-check", 0, True)
            run.assert_not_called()

    def test_configuration_failure_persists_safe_scheduled_history(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(traffic, "ROOT", Path(directory)),
            mock.patch.object(traffic.subprocess, "run") as run,
        ):
            ensure_equal(
                traffic.run_cycle(
                    {**configuration(), "mud_bad_traffic": False}, "scheduled"
                ),
                1,
            )
            observed = status(Path(directory))
            ensure_equal(observed["error_class"], "configuration")
            ensure_equal(observed["error_stage"], "configuration")
            ensure_equal(observed["failures"], ["mud_bad_traffic_required"])
            ensure("count" not in observed)
            ensure_equal(observed["history"][0]["status"], "failed")
            run.assert_not_called()

    def test_malformed_json_scheduled_attempt_records_failure(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(traffic, "ROOT", Path(directory)),
            mock.patch.object(traffic, "config", side_effect=ValueError("SECRET")),
            mock.patch.object(traffic.sys, "argv", ["tgen-control", "scheduled"]),
        ):
            ensure_equal(traffic.main(), 1)
            observed = status(Path(directory))
            ensure_equal(observed["error_class"], "configuration")
            ensure("SECRET" not in json.dumps(observed))

    def test_readiness_failure_preserves_history_after_stop(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(traffic, "ROOT", Path(directory)),
            mock.patch.object(
                traffic, "cheap_ready", side_effect=FileNotFoundError("SECRET")
            ),
            mock.patch.object(traffic.subprocess, "run"),
        ):
            authorize(Path(directory))
            ensure_equal(traffic.run_cycle(configuration(), "scheduled"), 1)
            with mock.patch.object(traffic.sys, "argv", ["tgen-control", "stop"]):
                ensure_equal(traffic.main(), 0)
            observed = status(Path(directory))
            ensure_equal(observed["error_class"], "tool_missing")
            ensure_equal(observed["error_stage"], "readiness")
            ensure_equal(observed["history"][0]["status"], "failed")
            ensure("SECRET" not in json.dumps(observed))

    def test_missing_metrics_are_failed_not_zero_and_never_echo_tool_output(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(traffic, "ROOT", Path(directory)),
            mock.patch.object(traffic, "cheap_ready"),
            mock.patch.object(
                traffic.subprocess,
                "run",
                side_effect=[
                    subprocess.CompletedProcess(["vegeta", "attack"], 0),
                    subprocess.CalledProcessError(
                        1, ["vegeta", "report"], output="SECRET"
                    ),
                ],
            ),
        ):
            authorize(Path(directory))
            ensure_equal(traffic.run_cycle(configuration(), "scheduled"), 1)
            observed = status(Path(directory))
            ensure_equal(observed["error_class"], "metrics_unavailable")
            ensure_equal(observed["error_stage"], "metrics")
            ensure("count" not in observed and "SECRET" not in json.dumps(observed))

    def test_missing_authorization_records_failed_run(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(traffic, "ROOT", Path(directory)),
            mock.patch.object(traffic, "cheap_ready") as ready,
        ):
            ensure_equal(traffic.run_cycle(configuration(), "scheduled"), 1)
            ready.assert_not_called()
            observed = status(Path(directory))
            ensure_equal(observed["status"], "failed")
            ensure_equal(len(observed["history"]), 1)
            ensure(not observed["scheduled_pair"])
            ensure_equal(observed["attribution_status"], "pending")

    def test_start_does_not_trigger_manual_burst(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(traffic, "ROOT", Path(directory)),
            mock.patch.object(traffic, "config", return_value=configuration()),
            mock.patch.object(traffic, "cheap_ready") as ready,
            mock.patch.object(traffic.subprocess, "run") as run,
            mock.patch.object(traffic.sys, "argv", ["tgen-control", "start"]),
        ):
            ensure_equal(traffic.main(), 0)
            ready.assert_called_once()
            run.assert_called_once_with(
                ["systemctl", "enable", "--now", "tgen-continuous.timer"], check=True
            )
            ensure((Path(directory) / "authorization.json").exists())

    def test_pinned_vegeta_capture_checks_origin_and_both_domains(self):
        with (
            mock.patch.object(
                traffic.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(
                    ["vegeta", "-version"], 0, stdout=VEGETA_VERSION
                ),
            ) as run,
            mock.patch.object(traffic.urllib.request, "build_opener") as build,
        ):
            build.return_value.open.return_value.__enter__.return_value.status = 200
            traffic.cheap_ready(configuration())
            run.assert_called_once_with(
                ["vegeta", "-version"], capture_output=True, text=True, check=True
            )
            ensure_equal(
                build.return_value.open.call_args_list,
                [
                    mock.call(f"http://{host}/health", timeout=5)
                    for host in ["192.0.2.1", *DOMAINS]
                ],
            )

    def test_wrong_vegeta_version_blocks_readiness_without_network(self):
        invalid = [
            "",
            *[
                VEGETA_VERSION.replace("v12.12.0", version)
                for version in (
                    "v12.12.1",
                    "12.12.0",
                    "v12.12.0-garbage",
                    "v12.12.0 garbage",
                )
            ],
            VEGETA_VERSION.replace("Version:", "Version :"),
            VEGETA_VERSION + "unexpected garbage\n",
            VEGETA_VERSION.replace("Commit:", "Unknown:"),
        ]
        for output in invalid:
            with (
                self.subTest(output=output),
                mock.patch.object(
                    traffic.subprocess,
                    "run",
                    return_value=subprocess.CompletedProcess(
                        ["vegeta", "-version"], 0, stdout=output
                    ),
                ),
                mock.patch.object(traffic.urllib.request, "build_opener") as build,
            ):
                with expect_error(ValueError, "mandatory pinned"):
                    traffic.cheap_ready(configuration())
                build.assert_not_called()

    def test_failed_or_missing_vegeta_blocks_readiness_without_network(self):
        for failure in (
            FileNotFoundError("vegeta"),
            subprocess.CalledProcessError(
                1, ["vegeta", "-version"], output=VEGETA_VERSION
            ),
        ):
            with (
                self.subTest(failure=type(failure).__name__),
                mock.patch.object(
                    traffic.subprocess, "run", side_effect=failure
                ) as run,
                mock.patch.object(traffic.urllib.request, "build_opener") as build,
            ):
                with expect_error(type(failure)):
                    traffic.cheap_ready(configuration())
                run.assert_called_once_with(
                    ["vegeta", "-version"], capture_output=True, text=True, check=True
                )
                build.assert_not_called()

    def test_real_missing_vegeta_fails_before_network(self):
        with (
            tempfile.TemporaryDirectory() as empty_path,
            mock.patch.dict(os.environ, {"PATH": empty_path}),
            mock.patch.object(traffic.urllib.request, "build_opener") as build,
        ):
            with expect_error(FileNotFoundError):
                traffic.cheap_ready(configuration())
            build.assert_not_called()


class AccountingTests(unittest.TestCase):
    def test_real_decoder_and_targets_bookkeeping_1499_to_1501(self):
        for count in (1499, 1500, 1501):
            with (
                self.subTest(count=count),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(traffic, "ROOT", Path(directory)),
                mock.patch.object(traffic, "cheap_ready"),
                mock.patch.object(
                    traffic.subprocess, "run", side_effect=FakeTool(count=count)
                ) as run,
            ):
                root = Path(directory)
                authorize(root)
                ensure_equal(traffic.run_cycle(configuration(), "scheduled"), 0)
                observed = status(root)
                ensure_equal(observed["count"], count)
                ensure_equal(observed["rate"], count / 30)
                ensure_equal(observed["duration_seconds"], 30)
                ensure_equal(
                    observed["class_counts"]["benign"], 1350 - max(0, 1500 - count)
                )
                ensure_equal(observed["transport_errors"], 0)
                ensure_equal(observed["http_errors"], 150 + max(0, count - 1500))
                ensure_equal(observed["response_failures"], 0)
                ensure_equal(observed["failures"], [])
                attack = run.call_args_list[0].args[0]
                ensure("-rate=50/s" in attack and "-duration=30s" in attack)

    def test_decoded_scheduled_capture_preserves_failed_history(self):
        for case in (
            "rate_refill",
            "fresh_rate",
            "missing_body",
            "blocking_page",
            "wrong_identity",
            "rate_403",
            "network",
            "aggregate_extra",
            "business",
        ):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(traffic, "ROOT", Path(directory)),
                mock.patch.object(traffic, "cheap_ready"),
                mock.patch.object(
                    traffic.subprocess, "run", side_effect=FakeTool(case=case)
                ),
            ):
                root = Path(directory)
                authorize(root)
                ensure_equal(
                    traffic.run_cycle(configuration(), "scheduled"),
                    int(case not in ("fresh_rate", "rate_refill")),
                )
                observed = status(root)
                ensure_equal(observed["count"], 1500)
                ensure_equal(observed["transport_errors"], int(case == "network"))
                ensure_equal(
                    observed["class_counts"],
                    {
                        "benign": 1350,
                        "rate-limit": 50,
                        "waf": 30,
                        "mud": 30,
                        "schema": 20,
                        "endpoint-denial": 20,
                    },
                )
                ensure_equal(len(observed["history"]), 1)
                ensure(not observed["scheduled_pair"])
                ensure_equal(observed["history"][0]["status"], observed["status"])
                ensure_equal(
                    observed["security_evidence_scope"], traffic.SECURITY_EVIDENCE_SCOPE
                )
                if case == "rate_refill":
                    ensure_equal(observed["benign_success"], 1)
                    ensure(
                        all(
                            outcome
                            == {
                                "status_counts": {"200": 25},
                                "429_count": 0,
                                "rate_denial_observed": False,
                            }
                            for outcome in observed["rate_outcomes"].values()
                        )
                    )
                    ensure_equal(traffic.evaluate_summary(observed, DOMAINS), [])
                if case in ("missing_body", "blocking_page", "wrong_identity"):
                    ensure("rate_origin_response_unconfirmed" in observed["failures"])
                    ensure_equal(observed["error_class"], "metrics_failed")
                if case == "rate_403":
                    ensure("unexpected_response" in observed["failures"])
                ensure(
                    (root / "results" / observed["run_id"] / "accounting.json").exists()
                )

    def test_scheduled_pressure_is_measurement_not_required_rate_proof(self):
        rows = records()
        bad = [
            {**row, "code": 403} if row["class"] == "rate-limit" else row
            for row in rows
        ]
        ensure("unexpected_response" in traffic.evaluate(report(), bad, DOMAINS))
        for row in rows:
            if row["class"] in ("rate-limit", "mud"):
                row["code"] = 200
        for domain in DOMAINS:
            next(
                row
                for row in rows
                if row["domain"] == domain and row["class"] == "rate-limit"
            )["code"] = 429
        ensure_equal(traffic.evaluate(report(), rows, DOMAINS), [])

    def test_rate_200_requires_actual_decodable_origin_echo(self):
        rows = records()
        row = rows[0]
        original_body = row["body"]
        row["code"] = 200
        for body in (
            None,
            "",
            "not base64",
            base64.b64encode(b"Forbidden").decode(),
            base64.b64encode(b"{}").decode(),
        ):
            row["body"] = body
            ensure(
                "rate_origin_response_unconfirmed"
                in traffic.evaluate(report(), rows, DOMAINS)
            )
        original = json.loads(base64.b64decode(original_body))
        for field, value in (
            ("method", "POST"),
            ("url", "http://other.example/anything/rate-limit"),
            ("headers", {"Host": row["domain"], "X-Mud-User": "other-user"}),
            (
                "headers",
                {"Host": "other.example", "X-Mud-User": "rate-limit-fresh-run"},
            ),
        ):
            row["body"] = base64.b64encode(
                json.dumps({**original, field: value}).encode()
            ).decode()
            ensure(
                "rate_origin_response_unconfirmed"
                in traffic.evaluate(report(), rows, DOMAINS)
            )
        row["body"] = original_body
        ensure_equal(traffic.evaluate(report(), rows, DOMAINS), [])

    def test_synthetic_bookkeeping(self):
        ensure_equal(traffic.evaluate(report(), records(), DOMAINS), [])

    def test_captured_first_burst_outcome_pattern(self):
        rows = records()
        for row in rows:
            row.update(
                code=200 if row["class"] in ("benign", "rate-limit") else 403,
                error=""
                if row["class"] in ("benign", "rate-limit")
                else "403 Forbidden",
            )
        measured = {
            **report(),
            "errors": ["403 Forbidden"],
            "rate": 50.03279007301814,
            "duration": 29_980_338_850,
        }
        ensure_equal(traffic.evaluate(measured, rows, DOMAINS), [])
        for outcome in traffic.rate_outcomes(rows, DOMAINS).values():
            ensure_equal(
                outcome,
                {
                    "status_counts": {"200": 25},
                    "429_count": 0,
                    "rate_denial_observed": False,
                },
            )
        ensure_equal(
            traffic.outcome_accounting(rows),
            {
                "transport_errors": 0,
                "http_errors": 100,
                "response_failures": 0,
                "benign_success": 1,
            },
        )
        for domain in DOMAINS:
            next(
                row
                for row in rows
                if row["domain"] == domain and row["class"] == "rate-limit"
            ).update(code=429, error="429 Too Many Requests")
        measured["errors"].append("429 Too Many Requests")
        ensure_equal(traffic.evaluate(measured, rows, DOMAINS), [])
        ensure_equal(traffic.outcome_accounting(rows)["transport_errors"], 0)

    def test_error_outcomes_fail_closed(self):
        for code, error in (
            (0, ""),
            (0, "403 Forbidden"),
            (0, "connection reset by peer"),
            (0, "read timeout"),
            (403, "read timeout"),
            (403, "429 Too Many Requests"),
            (200, "403 Forbidden"),
        ):
            with self.subTest(code=code, error=error):
                rows = records()
                rows[0].update(code=code, error=error)
                ensure(
                    "transport"
                    in traffic.evaluate(
                        {**report(), "errors": [error] if error else []}, rows, DOMAINS
                    )
                )
                ensure_equal(traffic.outcome_accounting(rows)["transport_errors"], 1)
        for malformed_code in (None, "403", True, -1, 999, 403.5):
            rows = records()
            rows[0]["code"] = malformed_code
            ensure("malformed_metrics" in traffic.evaluate(report(), rows, DOMAINS))
        rows = records()
        del rows[0]["code"]
        ensure("malformed_metrics" in traffic.evaluate(report(), rows, DOMAINS))
        for errors in (["unrelated aggregate error"], ["403 Forbidden"]):
            ensure(
                "error_accounting"
                in traffic.evaluate({**report(), "errors": errors}, records(), DOMAINS)
            )
        rows = records()
        rows[0]["error"] = "429 Too Many Requests"
        ensure("error_accounting" in traffic.evaluate(report(), rows, DOMAINS))

    def test_http_business_failure_is_not_transport(self):
        rows = records()
        next(row for row in rows if row["class"] == "benign").update(
            code=500, error="500 Internal Server Error"
        )
        failures = traffic.evaluate(
            {**report(), "errors": ["500 Internal Server Error"]}, rows, DOMAINS
        )
        ensure("unexpected_response" in failures and "transport" not in failures)
        ensure_equal(traffic.outcome_accounting(rows)["response_failures"], 1)
        ensure_equal(traffic.outcome_accounting(rows)["transport_errors"], 0)

    def test_malformed_metrics(self):
        for field in ("requests", "duration", "latencies", "errors"):
            bad = report()
            del bad[field]
            ensure("malformed_metrics" in traffic.evaluate(bad, records(), DOMAINS))
        for value in ("50", None, float("nan"), float("inf"), True):
            ensure(
                "malformed_metrics"
                in traffic.evaluate({**report(), "rate": value}, records(), DOMAINS)
            )

    def test_missing_domain(self):
        ensure(
            "domains"
            in traffic.evaluate(
                report(), [{**row, "domain": DOMAINS[0]} for row in records()], DOMAINS
            )
        )

    def test_count_and_mix(self):
        ensure(
            "mix"
            in traffic.evaluate(
                report(), [{**row, "class": "benign"} for row in records()], DOMAINS
            )
        )
        ensure("count" in traffic.evaluate(report(), records()[:-30], DOMAINS))

    def test_rate_and_duration(self):
        for value in (48.9, 51.1):
            ensure(
                "rate"
                in traffic.evaluate({**report(), "rate": value}, records(), DOMAINS)
            )
        ensure(
            "duration"
            in traffic.evaluate(
                {**report(), "duration": 29_000_000_000}, records(), DOMAINS
            )
        )

    def test_latency_failure(self):
        for key, value in (("99th", 100), ("max", 5_000_000_001), ("mean", 0)):
            bad = report()
            bad["latencies"][key] = value
            ensure("latencies" in traffic.evaluate(bad, records(), DOMAINS))

    def test_transport_and_unexpected_blocks(self):
        rows = records()
        rows[0].update(code=0, error="timeout")
        ensure("transport" in traffic.evaluate(report(), rows, DOMAINS))
        rows = records()
        for row in [row for row in rows if row["class"] == "benign"][:30]:
            row["code"] = 403
        ensure("benign_success" in traffic.evaluate(report(), rows, DOMAINS))
        rows = [
            {**row, "code": 200} if row["class"] != "benign" else row
            for row in records()
        ]
        ensure("expected_denial" in traffic.evaluate(report(), rows, DOMAINS))

    def test_second_scheduled_failure(self):
        history: list[dict[str, Any]] = [
            {"trigger": "scheduled", "status": "verified", "started_epoch": 1000},
            {"trigger": "scheduled", "status": "verified", "started_epoch": 1300},
        ]
        ensure(traffic.scheduled_pair(history))
        for key, value in (
            ("trigger", "manual"),
            ("status", "failed"),
            ("started_epoch", 1200),
        ):
            bad = copy.deepcopy(history)
            bad[-1][key] = value
            ensure(not traffic.scheduled_pair(bad))
        ensure(not traffic.scheduled_pair(history[:1]))
        ensure(not traffic.scheduled_pair([{}, {}]))


class AttemptTests(unittest.TestCase):
    def test_unexpected_unicode_exception_preserves_safe_failed_history(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(traffic, "ROOT", Path(directory)),
            mock.patch.object(
                traffic,
                "cheap_ready",
                side_effect=RuntimeError("SECRET snowman \u2603"),
            ),
            mock.patch.object(traffic.subprocess, "run") as run,
        ):
            root = Path(directory)
            authorize(root)
            ensure_equal(traffic.run_cycle(configuration(), "scheduled"), 1)
            observed = status(root)
            ensure_equal(observed["error_class"], "readiness_failed")
            ensure_equal(observed["error_stage"], "readiness")
            ensure_equal(observed["history"][0]["status"], "failed")
            ensure("SECRET" not in json.dumps(observed))
            ensure("count" not in observed)
            run.assert_not_called()

    def test_process_interrupts_propagate_without_failed_acceptance(self):
        for interruption in (KeyboardInterrupt(), SystemExit(17)):
            with (
                self.subTest(interruption=type(interruption).__name__),
                tempfile.TemporaryDirectory() as directory,
                mock.patch.object(traffic, "ROOT", Path(directory)),
                mock.patch.object(traffic, "cheap_ready", side_effect=interruption),
                mock.patch.object(traffic.subprocess, "run") as run,
            ):
                root = Path(directory)
                authorize(root)
                with expect_error(type(interruption)):
                    traffic.run_cycle(configuration(), "scheduled")
                ensure(not (root / "status.json").exists())
                ensure(not (root / "results/history.json").exists())
                run.assert_not_called()


class TargetTests(unittest.TestCase):
    def test_frontloaded_aggregate_budget(self):
        for sequence in (0, 1, 2, 14, 15):
            targets = traffic.targets(DOMAINS, f"fresh-{sequence}", sequence)
            ensure_equal(len(targets), 1500)
            ensure_equal(
                [target["header"]["X-Demo-Class"][0] for target in targets[:50]],
                ["rate-limit"] * 50,
            )
            ensure_equal(
                [
                    urllib.parse.urlsplit(target["url"]).hostname
                    for target in targets[:50]
                ],
                DOMAINS * 25,
            )
            ensure_equal((50 - 1) / 50, 0.98)
            ensure(
                all(
                    target["header"]["X-Demo-Class"] != ["rate-limit"]
                    for target in targets[50:]
                )
            )
            for domain in DOMAINS:
                subset = [
                    target
                    for target in targets
                    if urllib.parse.urlsplit(target["url"]).hostname == domain
                ]
                classes = [target["header"]["X-Demo-Class"][0] for target in subset]
                ensure_equal(len(subset), 750)
                ensure_equal(classes.count("benign"), 675)
                ensure_equal(classes.count("rate-limit"), 25)
                ensure_equal(set(classes), {"benign", *traffic.CLASSES})
                ensure_equal(
                    {
                        target["header"]["X-MUD-User"][0]
                        for target in subset
                        if target["header"]["X-Demo-Class"] == ["rate-limit"]
                    },
                    {f"rate-limit-fresh-{sequence}"},
                )
                identities = {
                    category: {
                        target["header"]["X-MUD-User"][0]
                        for target in subset
                        if target["header"]["X-Demo-Class"] == [category]
                    }
                    for category in set(classes)
                }
                for category, users in identities.items():
                    for other, other_users in identities.items():
                        if category != other:
                            ensure(not users & other_users)
            ensure_equal(
                {urllib.parse.urlsplit(target["url"]).hostname for target in targets},
                set(DOMAINS),
            )

    def test_valid_benign_schema_and_unique_classes(self):
        targets = traffic.targets(DOMAINS, "fresh-run", 0)
        for target in targets:
            ensure_equal(target["header"]["X-Demo-Run"], ["fresh-run"])
            if target["method"] == "POST" and target["header"]["X-Demo-Class"] == [
                "benign"
            ]:
                ensure_equal(
                    json.loads(base64.b64decode(target["body"])),
                    {"demo_id": "fresh-run"},
                )
        ensure(targets != traffic.targets(DOMAINS, "next-run", 1))
        with expect_error(ValueError):
            traffic.targets(DOMAINS, "run", 0, False)


if __name__ == "__main__":
    unittest.main()
