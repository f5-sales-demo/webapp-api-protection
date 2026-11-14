"""Every catalog use case needs fixtures, endpoint outputs and negative controls."""

import json
import unittest

from demo_catalog_acceptance import coverage_failures
from demo_lifecycle_fixtures import ROOT
from demo_test_support import ensure_equal


class RequiredCatalogMapping(unittest.TestCase):
    def test_every_missing_mapping_rejects_acceptance(self):
        manifest = json.loads((ROOT / "terraform/coverage/catalog.json").read_text())
        ensure_equal(coverage_failures(manifest), [])
        for key in (
            "terraform_owner",
            "entrypoint",
            "protected_endpoints",
            "endpoint_outputs",
            "fixture_owner",
            "negative_control",
        ):
            changed = json.loads(json.dumps(manifest))
            changed["entries"][0].pop(key)
            ensure_equal(coverage_failures(changed), [manifest["entries"][0]["id"]])

    def test_missing_shared_contract_rejects_referencing_entries(self):
        manifest = json.loads((ROOT / "terraform/coverage/catalog.json").read_text())
        manifest["fixtures"] = {}
        ensure_equal(
            coverage_failures(manifest), [entry["id"] for entry in manifest["entries"]]
        )
        manifest = json.loads((ROOT / "terraform/coverage/catalog.json").read_text())
        key = manifest["entries"][0]["negative_control"]
        manifest["negative_controls"].pop(key)
        ensure_equal(
            coverage_failures(manifest),
            [
                entry["id"]
                for entry in manifest["entries"]
                if entry["negative_control"] == key
            ],
        )
