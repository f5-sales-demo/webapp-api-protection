#!/usr/bin/env python3
"""Export real synthetic crAPI fixtures from the ownership-verified demo origin."""

import json
import os
import subprocess
from urllib.request import Request, urlopen

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


def seeded_ids() -> dict:
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
        input=SQL,
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
    result.update(
        fixture_type="seeded-synthetic-origin-accounts",
        crapi_tokens=[login(email, password) for email, password in ACCOUNTS],
    )
    return result


if __name__ == "__main__":
    os.umask(0o077)
    print(json.dumps(collect()))
