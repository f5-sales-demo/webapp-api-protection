"""Clean capacity, no-op repeat deployment and quota failure are distinct gates."""

import unittest
from typing import Any
from unittest.mock import Mock

from demo_lifecycle_capacity import QUOTA_TYPES, creation_needs, require_capacity
from demo_lifecycle_state import Blocked
from demo_test_support import ensure_equal, expect_error


def quota(needs):
    return {
        "quota_usage": {
            name: {"limit": {"maximum": count}, "usage": {"current": count}}
            for name, count in needs.items()
        }
    }


class PlannedCapacity(unittest.TestCase):
    def test_clean_inventory_counts_all_twelve_listeners_and_policies(self):
        counts = {
            "xcsh_http_loadbalancer": 12,
            "xcsh_app_firewall": 11,
            "xcsh_api_definition": 3,
            "xcsh_user_identification": 11,
            "xcsh_malicious_user_mitigation": 2,
            "xcsh_healthcheck": 1,
            "xcsh_origin_pool": 1,
            "xcsh_swagger_object": 2,
        }
        rows = [
            {
                "type": kind,
                "change": {
                    "actions": ["create"],
                    "after": {"https_auto_cert": {} if index < 11 else None},
                },
            }
            for kind, count in counts.items()
            for index in range(count)
        ]
        needs = creation_needs({"resource_changes": rows})
        ensure_equal(needs["HTTP Load Balancer"], 12)
        ensure_equal(needs["TLS Certificate"], 11)
        for kind, count in counts.items():
            ensure_equal(needs[QUOTA_TYPES[kind]], count)

    def test_repeat_at_full_quota_and_import_require_no_extra_capacity(self):
        plan = {
            "resource_changes": [
                {
                    "type": "xcsh_http_loadbalancer",
                    "change": {"actions": ["no-op"], "importing": {"id": "owned"}},
                }
            ]
        }
        needs = creation_needs(plan)
        runtime = Mock()
        runtime.xc.return_value = quota(needs)
        require_capacity(runtime, needs)
        ensure_equal(set(needs.values()), {0})

    def test_pending_deletion_does_not_credit_creation_and_quota_failure_blocks(self):
        needs = creation_needs(
            {
                "resource_changes": [
                    {
                        "type": "xcsh_app_firewall",
                        "change": {"actions": ["delete", "create"], "after": {}},
                    }
                ]
            }
        )
        runtime = Mock()
        runtime.xc.return_value = quota(needs)
        with expect_error(Blocked, "insufficient"):
            require_capacity(runtime, needs)

    def test_missing_malformed_quota_or_unknown_certificate_fails(self):
        runtime = Mock()
        defects: tuple[dict[str, Any], ...] = (
            {},
            {"quota_usage": {}},
            {
                "quota_usage": {
                    "HTTP Load Balancer": {
                        "limit": {"maximum": True},
                        "usage": {"current": 0},
                    }
                }
            },
        )
        for defect in defects:
            runtime.xc.return_value = defect
            with expect_error(Blocked):
                require_capacity(runtime, {"HTTP Load Balancer": 1})
        with expect_error(Blocked, "unknown"):
            creation_needs(
                {
                    "resource_changes": [
                        {
                            "type": "xcsh_http_loadbalancer",
                            "change": {
                                "actions": ["create"],
                                "after_unknown": {"https_auto_cert": True},
                            },
                        }
                    ]
                }
            )
