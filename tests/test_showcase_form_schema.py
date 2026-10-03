"""Native HTTPBin form remains valid without weakening the synthetic JSON contract."""

import json
import unittest
from pathlib import Path

from demo_test_support import ensure, ensure_equal


class ShowcaseFormSchemaTests(unittest.TestCase):
    def test_native_form_and_json_contracts_remain_distinct(self):
        root = Path(__file__).resolve().parents[1]
        spec = json.loads(
            (root / "terraform/fixtures/showcase-openapi.json").read_text()
        )
        content = spec["paths"]["/httpbin/post"]["post"]["requestBody"]["content"]
        ensure_equal(content["application/json"]["schema"]["required"], ["demo_id"])
        form = content["application/x-www-form-urlencoded"]["schema"]
        ensure_equal(form["type"], "object")
        ensure("custname" in form["properties"])
        ensure("comments" in form["properties"])
        ensure(
            all(value.get("nullable") is True for value in form["properties"].values())
        )


if __name__ == "__main__":
    unittest.main()
