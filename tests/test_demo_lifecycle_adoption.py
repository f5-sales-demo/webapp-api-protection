"""Reviewed adoption rejects stale scope, ownership and content before import."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from demo_lifecycle_adoption import adopt
from demo_lifecycle_state import Blocked, save_json
from demo_test_support import expect_error


class AdoptionTests(unittest.TestCase):
    def test_unreviewed_and_unpinned_identity_never_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = SimpleNamespace(
                paths=SimpleNamespace(state=root),
                settings=SimpleNamespace(scope={"namespace": "demo"}),
            )
            mapping = root / "review.json"
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
                        "imports": [entry],
                    },
                )
                with expect_error(Blocked):
                    adopt(context, terraform, mapping)
            terraform.tf.assert_not_called()

    def test_stale_plan_never_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = SimpleNamespace(
                paths=SimpleNamespace(state=root),
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
                            "id": "example/showcase-form-native/v1",
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
                    "name": "showcase-form-native",
                },
            }
            with (
                patch("demo_lifecycle_adoption.require_current"),
                expect_error(Blocked),
            ):
                adopt(context, terraform, mapping)
            terraform.tf.assert_not_called()
