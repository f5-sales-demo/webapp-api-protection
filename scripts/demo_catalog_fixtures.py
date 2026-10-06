#!/usr/bin/env python3
"""Export real synthetic crAPI fixtures from the ownership-verified demo origin."""

import argparse
import http.cookiejar
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen

RESTAURANT_SYNTHETIC_PASSWORD = "password"  # noqa: S105 - published synthetic lab account
ACCOUNTS = (
    ("adam007@example.com", "adam007!123"),
    ("pogba006@example.com", "pogba006!123"),
)
SQL = """
BEGIN;
INSERT INTO profile_video (id, conversion_params, video_name, user_id)
SELECT COALESCE((SELECT MAX(id) FROM profile_video),0)+1, '-v codec h264', 'tgen-synthetic.mp4', u.id
FROM user_login u WHERE u.email='adam007@example.com'
AND NOT EXISTS (SELECT 1 FROM profile_video WHERE user_id=u.id);
INSERT INTO "order" (id,quantity,created_on,status,product_id,user_id,transaction_id)
SELECT COALESCE((SELECT MAX(id) FROM "order"),0)+1,1,NOW(),'delivered',p.id,u.id,'tgen-synthetic'
FROM user_login u CROSS JOIN (SELECT id FROM product ORDER BY id LIMIT 1) p
WHERE u.email='adam007@example.com' AND NOT EXISTS (SELECT 1 FROM "order" WHERE user_id=u.id);
SELECT json_build_object(
'crapi_vehicle_uuid',(SELECT uuid FROM vehicle_details WHERE owner_id=(SELECT id FROM user_login WHERE email='adam007@example.com') ORDER BY id LIMIT 1),
'crapi_video_id',(SELECT id FROM profile_video WHERE user_id=(SELECT id FROM user_login WHERE email='adam007@example.com') ORDER BY id LIMIT 1),
'crapi_order_id',(SELECT id FROM "order" WHERE user_id=(SELECT id FROM user_login WHERE email='adam007@example.com') ORDER BY id LIMIT 1));
COMMIT;
"""


def seeded_ids(seed: bool = False) -> dict:
    """Create absent bounded synthetic fixtures and return actual database identities."""
    result = subprocess.run(
        [
            "/usr/bin/docker",
            "exec",
            "-i",
            "crapi-postgres",
            "psql",
            "-U",
            "admin",
            "-d",
            "crapi",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
        ],
        input=SQL
        if seed
        else SQL[SQL.index("SELECT json_build_object(") : SQL.index("COMMIT;")],
        text=True,
        capture_output=True,
        check=True,
        timeout=20,
    )
    return json.loads(result.stdout.strip())


def login(email: str, password: str) -> str:
    """Collect an origin-issued token using the public seeded account contract."""
    request = Request(
        "http://127.0.0.1:18888/identity/api/auth/login",
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=10) as response:  # noqa: S310 - fixed loopback HTTP origin
        token = json.load(response).get("token")
    if not isinstance(token, str) or not token:
        message = "synthetic origin login failed"
        raise ValueError(message)
    return token


def restaurant_fixtures(seed: bool = False) -> dict:
    """Seed bounded customer/Chef accounts through the demo application's own model."""
    code = "from db.session import SessionLocal; from db.models import UserRole; from apis.auth.utils import create_user_if_not_exists, update_user_password; db=SessionLocal(); create_user_if_not_exists(db,'tgen_customer','password','Synthetic','Customer','5550100001',UserRole.CUSTOMER); create_user_if_not_exists(db,'tgen_chef','password','Synthetic','Chef','5550100002',UserRole.CHEF); update_user_password(db,'tgen_customer','password'); update_user_password(db,'tgen_chef','password'); db.close()"
    if seed:
        subprocess.run(  # noqa: S603 - fixed owned container and synthetic seed code
            ["/usr/bin/docker", "exec", "restaurant-1", "python", "-c", code],
            check=True,
            capture_output=True,
            timeout=20,
        )
    result = {}
    for role in ("customer", "chef"):
        request = Request(
            "http://127.0.0.1:8301/token",
            data=urlencode(
                {"username": "tgen_" + role, "password": RESTAURANT_SYNTHETIC_PASSWORD}
            ).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urlopen(request, timeout=10) as response:  # noqa: S310 - fixed loopback HTTP origin
            result["restaurant_" + role + "_token"] = json.load(response)[
                "access_token"
            ]
    return result


def seed_dvwa_sessions() -> dict:
    """Authenticate actual synthetic sessions on all four declared DVWA replicas."""
    sessions = {}
    domains = (
        "www.f5-sales-demo.com",
        "api.f5-sales-demo.com",
        "waf-before.f5-sales-demo.com",
        "waf-after.f5-sales-demo.com",
    )
    for domain in domains:
        jar = http.cookiejar.CookieJar()
        opener = build_opener(HTTPCookieProcessor(jar))
        for port in (8101, 8102, 8103, 8104):
            base = f"http://127.0.0.1:{port}"
            with opener.open(base + "/login.php", timeout=10) as response:
                page = response.read().decode()
            token = re.search(
                r"name=['\"]user_token['\"][^>]*value=['\"]([^'\"]+)", page
            )
            if token is None:
                message = "native DVWA login token missing"
                raise ValueError(message)
            request = Request(  # noqa: S310 - declared loopback replica
                base + "/login.php",
                data=urlencode(
                    {
                        "username": "admin",
                        "password": "password",
                        "Login": "Login",
                        "user_token": token.group(1),
                    }
                ).encode(),
            )
            with opener.open(request, timeout=10) as response:
                if "Logout" not in response.read().decode():
                    message = "native DVWA synthetic login failed"
                    raise ValueError(message)
        cookie = next(
            (cookie.value for cookie in jar if cookie.name == "PHPSESSID"), None
        )
        if not isinstance(cookie, str) or not cookie:
            message = "origin-issued DVWA session missing"
            raise ValueError(message)
        sessions[domain] = cookie
    return sessions


def collect() -> dict:
    """Fail closed rather than exporting an absent prerequisite."""
    result = seeded_ids()
    if set(result) != {
        "crapi_vehicle_uuid",
        "crapi_video_id",
        "crapi_order_id",
    } or not all(result.values()):
        message = "seeded origin fixture identity missing"
        raise ValueError(message)
    result.update(restaurant_fixtures())
    seed_receipt = Path("/opt/origin-server/catalog-seed-sessions.json")
    if not seed_receipt.is_file() or seed_receipt.stat().st_mode & 0o077:
        message = "declared private DVWA seed receipt missing"
        raise ValueError(message)
    result["dvwa_sessions"] = json.loads(seed_receipt.read_text())
    result.update(
        fixture_type="seeded-synthetic-origin-accounts",
        crapi_tokens=[login(email, password) for email, password in ACCOUNTS],
    )
    return result


if __name__ == "__main__":
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", action="store_true")
    args = parser.parse_args()
    if args.seed:
        seeded_ids(seed=True)
        restaurant_fixtures(seed=True)
        receipt = Path("/opt/origin-server/catalog-seed-sessions.json")
        receipt.write_text(json.dumps(seed_dvwa_sessions()))
        receipt.chmod(0o600)
        print(json.dumps({"seeded": True}))
    else:
        print(json.dumps(collect()))
