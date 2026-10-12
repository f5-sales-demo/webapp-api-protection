"""Reviewed adoption rejects stale scope, ownership and content before import."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from demo_lifecycle_adoption import _move_listeners, adopt
from demo_lifecycle_state import Blocked, save_json
from demo_test_support import expect_error


class AdoptionTests(unittest.TestCase):
    def test_unreviewed_and_unpinned_identity_never_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = SimpleNamespace(
                paths=SimpleNamespace(state=root, app=root),
                settings=SimpleNamespace(scope={"namespace": "demo"}),
            )
            mapping = root / "review.json"
            (root / "application.tfstate").write_text("{}")
            (root / "fixtures").mkdir()
            (root / "fixtures/showcase-openapi.json").write_text("expected")
            terraform = Mock()
            for entry in (
                {
                    "address": "xcsh_swagger_object.showcase",
                    "id": "demo/showcase-form-native/latest",
                    "version": "latest",
                    "reviewed": True,
                },
                {
                    "address": "xcsh_swagger_object.showcase",
                    "id": "demo/showcase-form-native/v1",
                    "version": "v1",
                    "reviewed": False,
                },
                {
                    "address": "unknown",
                    "id": "demo/showcase-form-native/v1",
                    "version": "v1",
                    "reviewed": True,
                },
            ):
                save_json(
                    mapping,
                    {
                        "schema_version": 1,
                        "scope": context.settings.scope,
                        "state_sha256": hashlib.sha256(
                            (root / "application.tfstate").read_bytes()
                        ).hexdigest(),
                        "imports": [entry],
                    },
                )
                with (
                    patch("demo_lifecycle_adoption.require_current"),
                    expect_error(Blocked),
                ):
                    adopt(context, terraform, mapping)
            terraform.tf.assert_not_called()

    def test_stale_plan_never_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = SimpleNamespace(
                paths=SimpleNamespace(state=root, app=root),
                settings=SimpleNamespace(scope={"namespace": "demo"}),
            )
            mapping = root / "review.json"
            save_json(
                mapping,
                {
                    "schema_version": 1,
                    "scope": context.settings.scope,
                    "imports": [
                        {
                            "address": "xcsh_swagger_object.showcase",
                            "id": "demo/showcase-form-native/v1",
                            "version": "v1",
                            "reviewed": True,
                        }
                    ],
                },
            )
            terraform = Mock()
            with (
                patch(
                    "demo_lifecycle_adoption.require_current",
                    side_effect=Blocked("stale"),
                ),
                expect_error(Blocked),
            ):
                adopt(context, terraform, mapping)
            terraform.tf.assert_not_called()

    def test_live_content_mismatch_never_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "terraform"
            (app / "fixtures").mkdir(parents=True)
            state = root / "application.tfstate"
            state.write_text("{}")
            (app / "fixtures/showcase-openapi.json").write_text("expected")
            context = SimpleNamespace(
                paths=SimpleNamespace(state=root, app=app),
                settings=SimpleNamespace(scope={"namespace": "example"}),
            )
            mapping = root / "review.json"
            save_json(
                mapping,
                {
                    "schema_version": 1,
                    "scope": context.settings.scope,
                    "state_sha256": hashlib.sha256(state.read_bytes()).hexdigest(),
                    "imports": [
                        {
                            "address": "xcsh_swagger_object.showcase",
                            "id": "example/showcase-form-"
                            + hashlib.sha256(b"expected").hexdigest()[:32]
                            + "/v1",
                            "version": "v1",
                            "reviewed": True,
                            "sha256": hashlib.sha256(b"expected").hexdigest(),
                        }
                    ],
                },
            )
            terraform = Mock()
            terraform.runtime.xc.return_value = {
                "string_value": "changed",
                "metadata": {
                    "version": "v1",
                    "namespace": "example",
                    "name": "showcase-form-"
                    + hashlib.sha256(b"expected").hexdigest()[:32],
                },
            }
            with (
                patch("demo_lifecycle_adoption.require_current"),
                expect_error(Blocked),
            ):
                adopt(context, terraform, mapping)
            terraform.tf.assert_not_called()

    def test_listener_moves_preserve_exact_ids_and_resume(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = root / "application.tfstate"
            save_json(
                state,
                {
                    "resources": [
                        {
                            "module": "module.http_lb",
                            "type": "xcsh_http_loadbalancer",
                            "name": "this",
                            "instances": [{"attributes": {"id": "primary-id"}}],
                        },
                        {
                            "module": "module.http_lb",
                            "type": "xcsh_http_loadbalancer",
                            "name": "http",
                            "instances": [
                                {"index_key": 0, "attributes": {"id": "http-id"}}
                            ],
                        },
                    ]
                },
            )
            moves = [
                {
                    "from": "module.http_lb.xcsh_http_loadbalancer.this",
                    "to": 'module.http_lb.xcsh_http_loadbalancer.this["primary"]',
                    "id": "primary-id",
                },
                {
                    "from": "module.http_lb.xcsh_http_loadbalancer.http[0]",
                    "to": 'module.http_lb.xcsh_http_loadbalancer.this["http"]',
                    "id": "http-id",
                },
            ]
            context = SimpleNamespace(paths=SimpleNamespace(app=root))
            terraform = Mock()
            _move_listeners({"moves": moves}, state, terraform, context)
            assert terraform.tf.call_count == 2
            terraform.reset_mock()
            moves[0]["id"] = "foreign-id"
            with expect_error(Blocked):
                _move_listeners({"moves": moves}, state, terraform, context)
            terraform.tf.assert_not_called()

    def test_current_content_addressed_imports_validate_all_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = root / "terraform"
            (app / "fixtures").mkdir(parents=True)
            state = root / "application.tfstate"
            save_json(state, {"resources": []})
            context = SimpleNamespace(
                paths=SimpleNamespace(state=root, app=app, vars=root / "vars.json"),
                settings=SimpleNamespace(scope={"namespace": "example"}),
            )
            entries = []
            live = []
            for owner, prefix, filename in (
                ("showcase", "showcase-form-", "showcase-openapi.json"),
                ("comparison", "comparison-", "comparison-openapi.json"),
            ):
                content = "synthetic " + owner
                (app / "fixtures" / filename).write_text(content)
                digest = hashlib.sha256(content.encode()).hexdigest()
                name = prefix + digest[:32]
                entries.append(
                    {
                        "address": "xcsh_swagger_object." + owner,
                        "id": "example/" + name + "/v1",
                        "version": "v1",
                        "sha256": digest,
                        "reviewed": True,
                    }
                )
                live.append(
                    {
                        "string_value": content,
                        "metadata": {
                            "name": name,
                            "namespace": "example",
                            "version": "v1",
                        },
                    }
                )
            mapping = root / "review.json"
            document = {
                "schema_version": 1,
                "scope": context.settings.scope,
                "state_sha256": hashlib.sha256(state.read_bytes()).hexdigest(),
                "imports": entries,
                "moves": [],
            }
            save_json(mapping, document)
            terraform = Mock()
            terraform.runtime.xc.side_effect = [
                live[0],
                {**live[1], "string_value": "changed"},
            ]
            with (
                patch("demo_lifecycle_adoption.require_current"),
                expect_error(Blocked),
            ):
                adopt(context, terraform, mapping)
            terraform.tf.assert_not_called()
            terraform.runtime.xc.side_effect = live
            with patch("demo_lifecycle_adoption.require_current"):
                adopt(context, terraform, mapping)
            assert terraform.tf.call_count == 2
            assert [call.args[-1] for call in terraform.tf.call_args_list] == [
                entry["id"] for entry in entries
            ]
            receipt = __import__("json").loads(
                (root / "adoption-receipt.json").read_text()
            )
            assert (
                Path(receipt["backup"]) / "application.tfstate"
            ).read_bytes() == state.read_bytes()
