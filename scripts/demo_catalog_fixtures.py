#!/usr/bin/env python3
"""Export real synthetic crAPI fixtures from the ownership-verified demo origin."""

import argparse
import http.cookiejar
import json
import os
import re
import subprocess
from http import HTTPStatus
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen

RESTAURANT_SYNTHETIC_PASSWORD = "password"  # noqa: S105 - published synthetic lab account
ACCOUNTS = (
    ("adam007@example.com", "adam007!123"),
    ("pogba006@example.com", "pogba006!123"),
)
SQL = """
BEGIN;
INSERT INTO profile_video (id, conversion_params, video_name, video, user_id)
SELECT COALESCE((SELECT MAX(id) FROM profile_video),0)+1, '-v codec h264', 'tgen-synthetic.mp4', lo_from_bytea(0, decode('0000001c6674797069736f6d0000020069736f6d69736f326d7034310000037d6d6f6f760000006c6d766864000000000000000000000000000003e8000003e80001000001000000000000000000000000010000000000000000000000000000000100000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002000002a77472616b0000005c746b68640000000300000000000000000000000100000000000003e80000000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000004000000000a000000078000000000024656474730000001c656c73740000000000000001000003e800000000000100000000021f6d646961000000206d646864000000000000000000000000000028000000280055c400000000002d68646c72000000000000000076696465000000000000000000000000566964656f48616e646c657200000001ca6d696e6600000014766d68640000000100000000000000000000002464696e660000001c6472656600000000000000010000000c75726c20000000010000018a7374626c000000ea737473640000000000000001000000da6d70347600000000000000010000000000000000000000000000000000a000780048000000480000000000000001134c61766336302e33312e313032206d706567340000000000000000000000000018ffff000000606573647300000000038080804f0001000480808041201100000000030d40000017a0058080802f000001b001000001b58913000001000000012000c48d88005505040f1443000001b24c61766336302e33312e3130320680808001020000001070617370000000010000000100000014627472740000000000030d40000017a0000000187374747300000000000000010000000a0000040000000014737473730000000000000001000000010000001c737473630000000000000001000000010000000a000000010000003c7374737a00000000000000000000000a00000129000000330000003300000033000000330000003300000033000000330000003300000033000000147374636f0000000000000001000003a900000062756474610000005a6d657461000000000000002168646c7200000000000000006d6469726170706c0000000000000000000000002d696c737400000025a9746f6f0000001d6461746100000001000000004c61766636302e31362e3130300000000866726565000002fc6d646174000001b3001007000001b610c0a305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf700008a12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f00009412305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f00009e12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000a812305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000b212305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000bc12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000c612305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f000001b651e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b652c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b653e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b654c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b655e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b656c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b657e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b658c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b659e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f','hex')), u.id
FROM user_login u WHERE u.email='adam007@example.com'
AND NOT EXISTS (SELECT 1 FROM profile_video WHERE user_id=u.id);
UPDATE profile_video SET video=lo_from_bytea(0, decode('0000001c6674797069736f6d0000020069736f6d69736f326d7034310000037d6d6f6f760000006c6d766864000000000000000000000000000003e8000003e80001000001000000000000000000000000010000000000000000000000000000000100000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002000002a77472616b0000005c746b68640000000300000000000000000000000100000000000003e80000000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000004000000000a000000078000000000024656474730000001c656c73740000000000000001000003e800000000000100000000021f6d646961000000206d646864000000000000000000000000000028000000280055c400000000002d68646c72000000000000000076696465000000000000000000000000566964656f48616e646c657200000001ca6d696e6600000014766d68640000000100000000000000000000002464696e660000001c6472656600000000000000010000000c75726c20000000010000018a7374626c000000ea737473640000000000000001000000da6d70347600000000000000010000000000000000000000000000000000a000780048000000480000000000000001134c61766336302e33312e313032206d706567340000000000000000000000000018ffff000000606573647300000000038080804f0001000480808041201100000000030d40000017a0058080802f000001b001000001b58913000001000000012000c48d88005505040f1443000001b24c61766336302e33312e3130320680808001020000001070617370000000010000000100000014627472740000000000030d40000017a0000000187374747300000000000000010000000a0000040000000014737473730000000000000001000000010000001c737473630000000000000001000000010000000a000000010000003c7374737a00000000000000000000000a00000129000000330000003300000033000000330000003300000033000000330000003300000033000000147374636f0000000000000001000003a900000062756474610000005a6d657461000000000000002168646c7200000000000000006d6469726170706c0000000000000000000000002d696c737400000025a9746f6f0000001d6461746100000001000000004c61766636302e31362e3130300000000866726565000002fc6d646174000001b3001007000001b610c0a305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf700008a12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f00009412305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f00009e12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000a812305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000b212305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000bc12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000c612305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f000001b651e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b652c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b653e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b654c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b655e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b656c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b657e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b658c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b659e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f','hex')) WHERE video IS NULL AND video_name='tgen-synthetic.mp4' AND user_id=(SELECT id FROM user_login WHERE email='adam007@example.com');
DO $$ BEGIN PERFORM lo_put(video,0,decode('0000001c6674797069736f6d0000020069736f6d69736f326d7034310000037d6d6f6f760000006c6d766864000000000000000000000000000003e8000003e80001000001000000000000000000000000010000000000000000000000000000000100000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002000002a77472616b0000005c746b68640000000300000000000000000000000100000000000003e80000000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000004000000000a000000078000000000024656474730000001c656c73740000000000000001000003e800000000000100000000021f6d646961000000206d646864000000000000000000000000000028000000280055c400000000002d68646c72000000000000000076696465000000000000000000000000566964656f48616e646c657200000001ca6d696e6600000014766d68640000000100000000000000000000002464696e660000001c6472656600000000000000010000000c75726c20000000010000018a7374626c000000ea737473640000000000000001000000da6d70347600000000000000010000000000000000000000000000000000a000780048000000480000000000000001134c61766336302e33312e313032206d706567340000000000000000000000000018ffff000000606573647300000000038080804f0001000480808041201100000000030d40000017a0058080802f000001b001000001b58913000001000000012000c48d88005505040f1443000001b24c61766336302e33312e3130320680808001020000001070617370000000010000000100000014627472740000000000030d40000017a0000000187374747300000000000000010000000a0000040000000014737473730000000000000001000000010000001c737473630000000000000001000000010000000a000000010000003c7374737a00000000000000000000000a00000129000000330000003300000033000000330000003300000033000000330000003300000033000000147374636f0000000000000001000003a900000062756474610000005a6d657461000000000000002168646c7200000000000000006d6469726170706c0000000000000000000000002d696c737400000025a9746f6f0000001d6461746100000001000000004c61766636302e31362e3130300000000866726565000002fc6d646174000001b3001007000001b610c0a305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf700008a12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f00009412305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f00009e12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000a812305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000b212305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000bc12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000c612305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f000001b651e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b652c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b653e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b654c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b655e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b656c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b657e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b658c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b659e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f','hex')) FROM profile_video WHERE video IS NOT NULL AND video_name='tgen-synthetic.mp4' AND user_id=(SELECT id FROM user_login WHERE email='adam007@example.com') AND lo_get(video)<>decode('0000001c6674797069736f6d0000020069736f6d69736f326d7034310000037d6d6f6f760000006c6d766864000000000000000000000000000003e8000003e80001000001000000000000000000000000010000000000000000000000000000000100000000000000000000000000004000000000000000000000000000000000000000000000000000000000000002000002a77472616b0000005c746b68640000000300000000000000000000000100000000000003e80000000000000000000000000000000000010000000000000000000000000000000100000000000000000000000000004000000000a000000078000000000024656474730000001c656c73740000000000000001000003e800000000000100000000021f6d646961000000206d646864000000000000000000000000000028000000280055c400000000002d68646c72000000000000000076696465000000000000000000000000566964656f48616e646c657200000001ca6d696e6600000014766d68640000000100000000000000000000002464696e660000001c6472656600000000000000010000000c75726c20000000010000018a7374626c000000ea737473640000000000000001000000da6d70347600000000000000010000000000000000000000000000000000a000780048000000480000000000000001134c61766336302e33312e313032206d706567340000000000000000000000000018ffff000000606573647300000000038080804f0001000480808041201100000000030d40000017a0058080802f000001b001000001b58913000001000000012000c48d88005505040f1443000001b24c61766336302e33312e3130320680808001020000001070617370000000010000000100000014627472740000000000030d40000017a0000000187374747300000000000000010000000a0000040000000014737473730000000000000001000000010000001c737473630000000000000001000000010000000a000000010000003c7374737a00000000000000000000000a00000129000000330000003300000033000000330000003300000033000000330000003300000033000000147374636f0000000000000001000003a900000062756474610000005a6d657461000000000000002168646c7200000000000000006d6469726170706c0000000000000000000000002d696c737400000025a9746f6f0000001d6461746100000001000000004c61766636302e31362e3130300000000866726565000002fc6d646174000001b3001007000001b610c0a305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf700008a12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f00009412305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f00009e12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000a812305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000b212305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000bc12305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f0000c612305436c0f00b636dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf8db6fe36dbf7f000001b651e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b652c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b653e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b654c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b655e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b656c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b657e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b658c047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f000001b659e047ff7f00008a13ff7f00009413ff7f00009e13ff7f0000a813ff7f0000b213ff7f0000bc13ff7f0000c613ff7f','hex'); END $$;
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
    code = "from db.session import SessionLocal\nfrom db.models import User, UserRole\nfrom apis.auth.utils import create_user_if_not_exists, update_user_password\nfrom apis.auth.utils.utils import verify_password\ndb = SessionLocal()\nfor name, phone, role in (\n    ('tgen_customer', '5550100001', UserRole.CUSTOMER),\n    ('tgen_chef', '5550100002', UserRole.CHEF),\n    ('tgen_bola_attacker', '5550100003', UserRole.CUSTOMER),\n    ('tgen_bola_victim', '5550100004', UserRole.CUSTOMER),\n    ('tgen_bola_admin', '5550100005', UserRole.CHEF),\n    ('tgen_bola_chef', '5550100006', UserRole.CHEF),\n    ('tgen_bola_manager', '5550100007', UserRole.EMPLOYEE),\n    ('tgen_bola_root', '5550100008', UserRole.CHEF),\n):\n    user = db.query(User).filter(User.username == name).first()\n    if user is None:\n        create_user_if_not_exists(db, name, 'password', 'Synthetic', name, phone, role)\n        user = db.query(User).filter(User.username == name).one()\n    if not verify_password('password', user.password):\n        update_user_password(db, name, 'password')\n    user.role = role\n    user.phone_number = phone\n    user.first_name = 'Synthetic'\n    user.last_name = name\n    db.add(user)\ndb.commit()\ndb.close()\n"
    if seed:
        subprocess.run(  # noqa: S603 - fixed owned container and synthetic seed code
            ["/usr/bin/docker", "exec", "restaurant-1", "python", "-c", code],
            check=True,
            capture_output=True,
            timeout=20,
        )
    result = {}
    for role in (
        "customer",
        "chef",
        "attacker",
        "victim",
        "admin",
        "manager",
        "root",
        "bola_chef",
    ):
        username = (
            "tgen_" + role
            if role in ("customer", "chef")
            else "tgen_bola_" + role.removeprefix("bola_")
        )
        request = Request(
            "http://127.0.0.1:8301/token",
            data=urlencode(
                {"username": username, "password": RESTAURANT_SYNTHETIC_PASSWORD}
            ).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urlopen(request, timeout=10) as response:  # noqa: S310 - fixed loopback HTTP origin
            result["restaurant_" + role + "_token"] = json.load(response)[
                "access_token"
            ]
        if role not in ("customer", "chef"):
            result["restaurant_" + role] = {
                "username": username,
                "token": result["restaurant_" + role + "_token"],
            }
    return result


def seed_dvwa_sessions(username: str = "admin") -> dict:
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
                        "username": username,
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


def seed_dvwa_csrf() -> None:
    """Own one dedicated synthetic account without changing upstream admin fixtures."""
    sql = "INSERT INTO users (user_id,first_name,last_name,user,password,avatar) SELECT (SELECT COALESCE(MAX(u.user_id),0)+1 FROM users u),'Synthetic','CSRF','tgen_csrf',MD5('password'),'dvwa/images/admin.jpg' WHERE NOT EXISTS (SELECT 1 FROM users WHERE user='tgen_csrf'); UPDATE users SET password=MD5('password') WHERE user='tgen_csrf' AND password<>MD5('password');"
    subprocess.run(  # noqa: S603 - fixed synthetic account seed
        [
            "/usr/bin/docker",
            "exec",
            "dvwa-db",
            "mariadb",
            "-udvwa",
            "-pp@ssw0rd",
            "dvwa",
            "-e",
            sql,
        ],
        check=True,
        capture_output=True,
        timeout=20,
    )


def disposable_video_actor(
    email: str = "tgen-video@example.com",
    password: str = "SyntheticVideo!123",  # noqa: S107 - synthetic lab account
    number: str = "2025550188",
) -> str:
    """Own a bounded regular account isolated from seeded vehicle/community workflows."""
    try:
        return login(email, password)
    except HTTPError as error:
        if error.code != HTTPStatus.UNAUTHORIZED:
            raise
        error.close()
    request = Request(
        "http://127.0.0.1:18888/identity/api/auth/signup",
        data=json.dumps(
            {
                "name": "Example Video",
                "email": email,
                "number": number,
                "password": password,
            }
        ).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=20) as response:  # noqa: S310 - fixed loopback origin
        if response.status != HTTPStatus.OK:
            message = "disposable video actor signup failed"
            raise ValueError(message)
    return login(email, password)


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
    seeded = json.loads(seed_receipt.read_text())
    result["dvwa_sessions"] = seeded["dvwa_sessions"]
    result["dvwa_csrf_sessions"] = seeded["dvwa_csrf_sessions"]
    result["crapi_video_actor_token"] = login(
        "tgen-video@example.com", "SyntheticVideo!123"
    )
    result["crapi_order_actor_token"] = login(
        "tgen-order@example.com", "SyntheticOrder!123"
    )
    order = subprocess.run(
        [
            "/usr/bin/docker",
            "exec",
            "crapi-postgres",
            "psql",
            "-U",
            "admin",
            "-d",
            "crapi",
            "-qAt",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "SELECT id FROM \"order\" WHERE user_id=(SELECT id FROM user_login WHERE email='tgen-order@example.com') ORDER BY id LIMIT 1",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    result["crapi_dedicated_order_id"] = int(order.stdout.strip())
    result["crapi_otp_email"] = "tgen-otp@example.com"
    result["crapi_otp_password"] = "SyntheticOTP!123"  # noqa: S105 - synthetic lab fixture
    result["crapi_otp_actor_token"] = login(
        result["crapi_otp_email"], result["crapi_otp_password"]
    )
    request = Request(
        "http://127.0.0.1:5101/users/v1/login",
        data=json.dumps({"username": "name1", "password": "pass1"}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urlopen(request, timeout=10) as response:  # noqa: S310 - fixed loopback origin
        result["vampi_token"] = json.load(response)["auth_token"]
    with urlopen(
        "http://127.0.0.1:3001/rest/admin/application-configuration", timeout=10
    ) as response:
        application = json.load(response)["config"]["application"]
    result["juice_email"] = "admin@" + application["domain"]
    result["juice_password"] = "admin123"  # noqa: S105 - synthetic lab fixture
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
        seed_dvwa_csrf()
        disposable_video_actor()
        disposable_video_actor("tgen-otp@example.com", "SyntheticOTP!123", "2025550189")
        receipt.write_text(
            json.dumps(
                {
                    "dvwa_sessions": seed_dvwa_sessions(),
                    "dvwa_csrf_sessions": seed_dvwa_sessions("tgen_csrf"),
                }
            )
        )
        receipt.chmod(0o600)
        print(json.dumps({"seeded": True}))
    else:
        print(json.dumps(collect()))
