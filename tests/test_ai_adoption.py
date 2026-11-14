"""AI import authorization rejects live replacement and managed-policy drift."""

import copy
import hashlib
import json
import uuid
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from demo_lifecycle_adoption import adopt
from demo_lifecycle_ai_adoption import (
    LABELS,
    OWNERS,
    policy_digest,
    validate_ai_imports,
)
from demo_lifecycle_state import Blocked, save_json


def reviewed_objects():
    entries, live = [], {}
    listings: dict[str, dict] = {}
    for index, (address, (collection, name)) in enumerate(OWNERS.items()):
        uid = str(uuid.UUID(int=index + 1))
        obj = {
            "metadata": {"name": name, "namespace": "example", "labels": LABELS.copy()},
            "spec": {"synthetic_policy": name},
        }
        path = "/api/config/namespaces/example/" + collection
        live[path + "/" + name] = obj
        listings.setdefault(path, {"items": []})["items"].append(
            {"name": name, "namespace": "example", "uid": uid}
        )
        entries.append(
            {
                "address": address,
                "collection": collection,
                "id": "example/" + name,
                "uid": uid,
                "labels": LABELS.copy(),
                "policy_sha256": policy_digest(obj, collection),
                "reviewed": True,
            }
        )
    live.update(listings)
    terraform = Mock()
    terraform.runtime.xc.side_effect = lambda path: live[path]
    context = SimpleNamespace(settings=SimpleNamespace(scope={"namespace": "example"}))
    return context, terraform, entries, live


def test_complete_reviewed_set_uses_exact_live_uid_and_policy():
    context, terraform, entries, _ = reviewed_objects()
    validate_ai_imports(context, terraform, entries)
    assert terraform.runtime.xc.call_count == 9
    terraform.tf.assert_not_called()


@pytest.mark.parametrize(
    "mutation",
    [
        "partial",
        "duplicate",
        "unknown",
        "unreviewed",
        "uid",
        "namespace",
        "labels",
        "collection",
        "digest",
    ],
)
def test_incomplete_or_unreviewed_mapping_never_imports(mutation):
    context, terraform, entries, _ = reviewed_objects()
    if mutation == "partial":
        entries.pop()
    elif mutation == "duplicate":
        entries[-1] = copy.deepcopy(entries[0])
    elif mutation == "unknown":
        entries[0]["address"] = "module.unrelated.xcsh_app_firewall.this"
    else:
        key, value = {
            "unreviewed": ("reviewed", False),
            "uid": ("uid", "invalid"),
            "namespace": ("id", "other/ai-waf-before-waf"),
            "labels": ("labels", {}),
            "collection": ("collection", "origin_pools"),
            "digest": ("policy_sha256", "0" * 64),
        }[mutation]
        entries[0][key] = value
    with pytest.raises(Blocked):
        validate_ai_imports(context, terraform, entries)
    terraform.tf.assert_not_called()


@pytest.mark.parametrize(
    "mutation",
    ["replaced_uid", "foreign_namespace", "labels", "policy", "duplicate_inventory"],
)
def test_live_identity_or_managed_drift_never_imports(mutation):
    context, terraform, entries, live = reviewed_objects()
    collection, name = OWNERS[entries[-1]["address"]]
    path = "/api/config/namespaces/example/" + collection
    if mutation == "replaced_uid":
        live[path]["items"][-1]["uid"] = str(uuid.UUID(int=99))
    elif mutation == "foreign_namespace":
        live[path + "/" + name]["metadata"]["namespace"] = "other"
    elif mutation == "labels":
        live[path + "/" + name]["metadata"]["labels"]["demo-owner"] = "other"
    elif mutation == "policy":
        live[path + "/" + name]["spec"]["enable_malicious_user_detection"] = {}
    else:
        live[path]["items"].append(copy.deepcopy(live[path]["items"][-1]))
    with pytest.raises(Blocked):
        validate_ai_imports(context, terraform, entries)
    terraform.tf.assert_not_called()


def test_digest_ignores_only_operational_listener_fields_and_keeps_route_identity():
    obj: dict = {
        "spec": {
            "state": "Ready",
            "routes": [{"simple_route": {"uuid": str(uuid.UUID(int=1))}}],
        }
    }
    digest = policy_digest(obj, "http_loadbalancers")
    obj["spec"]["state"] = "Pending"
    assert policy_digest(obj, "http_loadbalancers") == digest
    obj["spec"]["routes"][0]["simple_route"]["uuid"] = str(uuid.UUID(int=2))
    assert policy_digest(obj, "http_loadbalancers") != digest


def import_into_state(state, address, identity):
    snapshot = json.loads(state.read_text())
    module, kind, tail = address.rsplit(".", 2)
    phase = json.loads(tail.removeprefix("this[").removesuffix("]"))
    snapshot["resources"].append(
        {
            "module": module,
            "type": kind,
            "name": "this",
            "instances": [
                {
                    "index_key": phase,
                    "attributes": {
                        "id": identity.split("/")[1],
                        "namespace": identity.split("/")[0],
                        "name": identity.split("/")[1],
                    },
                }
            ],
        }
    )
    save_json(state, snapshot)


def adoption_fixture(tmp_path):
    context, terraform, entries, _ = reviewed_objects()
    context.paths = SimpleNamespace(
        state=tmp_path, app=tmp_path, vars=tmp_path / "vars.json"
    )
    state = tmp_path / "application.tfstate"
    save_json(state, {"resources": []})
    mapping = tmp_path / "adoption-review.json"
    document = {
        "schema_version": 1,
        "scope": context.settings.scope,
        "imports": entries,
        "state_sha256": hashlib.sha256(state.read_bytes()).hexdigest(),
    }
    save_json(mapping, document)
    return context, terraform, entries, state, mapping, document


def test_interrupted_import_preserves_progress_and_requires_fresh_review_for_resume(
    tmp_path,
):
    context, terraform, entries, state, mapping, document = adoption_fixture(tmp_path)
    original = state.read_bytes()

    def interrupted(*args):
        import_into_state(state, args[-2], args[-1])
        if terraform.tf.call_count == 2:
            raise KeyboardInterrupt

    terraform.tf.side_effect = interrupted
    with (
        patch("demo_lifecycle_adoption.require_current"),
        pytest.raises(KeyboardInterrupt),
    ):
        adopt(context, terraform, mapping)
    receipt = json.loads((tmp_path / "adoption-receipt.json").read_text())
    assert receipt["status"] == "failed"
    assert receipt["completed"] == entries[:1]
    backup = __import__("pathlib").Path(receipt["backup"])
    assert (backup / "application.tfstate").read_bytes() == original
    assert (
        json.loads((backup / "progress.json").read_text())["error_type"]
        == "KeyboardInterrupt"
    )
    terraform.reset_mock()
    with (
        patch("demo_lifecycle_adoption.require_current"),
        pytest.raises(Blocked, match="state changed"),
    ):
        adopt(context, terraform, mapping)
    terraform.tf.assert_not_called()
    # Resume requires a freshly bound plan and reviewed current-state mapping.
    document["state_sha256"] = hashlib.sha256(state.read_bytes()).hexdigest()
    save_json(mapping, document)
    terraform.tf.side_effect = lambda *args: import_into_state(
        state, args[-2], args[-1]
    )
    with patch("demo_lifecycle_adoption.require_current"):
        adopt(context, terraform, mapping)
    assert terraform.tf.call_count == 4
    final = json.loads((tmp_path / "adoption-receipt.json").read_text())
    assert final["status"] == "passed"
    assert final["already_owned"] == entries[:2]
    assert final["completed"] == entries[2:]
    assert json.loads((backup / "progress.json").read_text())["status"] == "failed"


@pytest.mark.parametrize("foreign_owner", [False, True])
def test_state_identity_conflicts_rejected_before_any_import(tmp_path, foreign_owner):
    context, terraform, entries, state, mapping, document = adoption_fixture(tmp_path)
    entry = entries[0]
    address = (
        entry["address"].replace('use_case["ai-waf"]', 'use_case["foreign"]')
        if foreign_owner
        else entry["address"]
    )
    identity = entry["id"] if foreign_owner else "example/foreign-waf"
    import_into_state(state, address, identity)
    document["state_sha256"] = hashlib.sha256(state.read_bytes()).hexdigest()
    save_json(mapping, document)
    with patch("demo_lifecycle_adoption.require_current"), pytest.raises(Blocked):
        adopt(context, terraform, mapping)
    terraform.tf.assert_not_called()
    assert not (tmp_path / "adoption-receipt.json").exists()


def test_post_import_live_replacement_retains_failed_completed_receipt(tmp_path):
    context, terraform, entries, state, mapping, _ = adoption_fixture(tmp_path)
    original_xc = terraform.runtime.xc.side_effect

    def imported(*args):
        import_into_state(state, args[-2], args[-1])
        if terraform.tf.call_count == 6:

            def replaced(path):
                value = copy.deepcopy(original_xc(path))
                if path.endswith("/app_firewalls"):
                    value["items"][0]["uid"] = str(uuid.UUID(int=99))
                return value

            terraform.runtime.xc.side_effect = replaced

    terraform.tf.side_effect = imported
    with (
        patch("demo_lifecycle_adoption.require_current"),
        pytest.raises(Blocked, match="identity changed"),
    ):
        adopt(context, terraform, mapping)
    receipt = json.loads((tmp_path / "adoption-receipt.json").read_text())
    assert receipt["status"] == "failed"
    assert receipt["completed"] == entries
    assert len(json.loads(state.read_text())["resources"]) == 6


def test_platform_discovery_label_requires_exact_listener_identity():
    context, terraform, entries, live = reviewed_objects()
    for collection, name in OWNERS.values():
        if collection == "http_loadbalancers":
            path = "/api/config/namespaces/example/" + collection + "/" + name
            live[path]["metadata"]["labels"]["ves.io/app_type"] = (
                "ves-io-example-" + name
            )
    validate_ai_imports(context, terraform, entries)
    path = "/api/config/namespaces/example/http_loadbalancers/ai-waf-before"
    live[path]["metadata"]["labels"]["ves.io/app_type"] = "ves-io-example-foreign"
    with pytest.raises(Blocked, match="ownership"):
        validate_ai_imports(context, terraform, entries)
    live[path]["metadata"]["labels"]["ves.io/app_type"] = "ves-io-example-ai-waf-before"
    live[path]["metadata"]["labels"]["unknown-owner"] = "example"
    with pytest.raises(Blocked, match="ownership"):
        validate_ai_imports(context, terraform, entries)
