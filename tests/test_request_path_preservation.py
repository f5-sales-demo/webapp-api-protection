"""Declared native URI preservation remains equivalent across comparison hosts."""

import json
import unittest

import hcl2
from demo_lifecycle_fixtures import ROOT
from demo_test_support import ensure, ensure_equal
from test_demo_lifecycle_terraform import expression


class NativeRequestPaths(unittest.TestCase):
    def test_showcase_preserves_native_request_paths_on_every_https_listener(self):
        profile = json.loads((ROOT / "terraform/showcase.tfvars.json").read_text())
        ensure(profile["preserve_native_request_paths"] is True)
        config = hcl2.loads((ROOT / "terraform/main.tf").read_text())
        module = next(
            block["http_lb"] for block in config["module"] if "http_lb" in block
        )
        ensure_equal(
            expression(module, "preserve_native_request_paths"),
            "${var.preserve_native_request_paths}",
        )
        pairs = hcl2.loads((ROOT / "terraform/use_cases.tf").read_text())
        comparison = next(
            block["use_case"] for block in pairs["module"] if "use_case" in block
        )
        ensure_equal(
            expression(comparison, "preserve_native_request_paths"),
            "${var.preserve_native_request_paths}",
        )
        for source in ("modules/http-lb/main.tf", "modules/comparison/main.tf"):
            parsed = hcl2.loads((ROOT / "terraform" / source).read_text())
            listener = next(
                values
                for block in parsed["resource"]
                for kind, resources in block.items()
                if kind == "xcsh_http_loadbalancer"
                for values in resources.values()
            )
            https = listener.get("https_auto_cert")
            if https is None:
                dynamic = next(
                    block["https_auto_cert"]
                    for block in listener["dynamic"]
                    if "https_auto_cert" in block
                )
                https = dynamic["content"]
            value = https[0]
            ensure_equal(
                expression(value, "disable_path_normalize"),
                "${var.preserve_native_request_paths ? {} : None}",
            )
            ensure_equal(
                expression(value, "enable_path_normalize"),
                "${var.preserve_native_request_paths ? None : {}}",
            )
