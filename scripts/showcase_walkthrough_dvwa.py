"""Authenticated native DVWA probes; retain HTML and harmless browser markers."""

from __future__ import annotations

import hashlib
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING

from demo_verify_client import APPLICATION_BOUND, HTTP, Client
from showcase_walkthrough_config import fail

if TYPE_CHECKING:
    from pathlib import Path

SUCCESS, FORBIDDEN, MIN_ROWS = 200, 403, 2
MARKER = "<script>document.title='waap-synthetic-marker'</script>"
SQL = "1' OR '1'='1"


def probe(
    client: Client, host: str, path: str, user: str, session: str, label: str
) -> dict:
    """Dispatch through the public HTTPS route with an existing synthetic session."""
    if not re.fullmatch(r"[A-Za-z0-9,-]{8,128}", session):
        fail("valid origin-issued DVWA session required")
    started = time.time()
    request = urllib.request.Request(
        "https://" + host + path,
        headers={
            "X-MUD-User": user,
            "Cookie": "PHPSESSID=" + session + "; security=low",
        },
    )
    try:
        with HTTP.open(request, timeout=client.remaining()) as response:
            status, raw = response.status, response.read(APPLICATION_BOUND + 1)
    except urllib.error.HTTPError as exc:
        with exc:
            status, raw = exc.code, exc.read(APPLICATION_BOUND + 1)
    if len(raw) > APPLICATION_BOUND:
        fail("DVWA response exceeded bound")
    html = raw.decode("utf-8")
    record = {
        "host": host,
        "path": path.split("?", 1)[0],
        "request_target": path,
        "method": "GET",
        "user": user,
        "sent_at": started,
        "received_at": time.time(),
        "status": status,
        "body": html,
        "payload_sha256": hashlib.sha256(path.encode()).hexdigest(),
        "control": "" if label.startswith("legitimate") else "waf",
        "label": label,
    }

    if hasattr(client, "walkthrough_directory"):
        with (client.walkthrough_directory / "requests.jsonl").open("a") as stream:
            stream.write(json.dumps(record) + "\n")
    return record


def requests(
    client: Client, host: str, prefix: str, session: str, enabled: bool
) -> list[dict]:
    """Launch one SQL injection and one harmless reflected marker, then valid inputs."""
    cases = [
        ("sql", "/dvwa/vulnerabilities/sqli/", {"id": SQL, "Submit": "Submit"}),
        ("xss", "/dvwa/vulnerabilities/xss_r/", {"name": MARKER}),
        (
            "legitimate-sql",
            "/dvwa/vulnerabilities/sqli/",
            {"id": "1", "Submit": "Submit"},
        ),
        (
            "legitimate-xss",
            "/dvwa/vulnerabilities/xss_r/",
            {"name": "synthetic visitor"},
        ),
    ]
    result = [
        probe(
            client,
            host,
            path + "?" + urllib.parse.urlencode(payload),
            prefix + "-" + label,
            session,
            label,
        )
        for label, path, payload in cases
    ]
    for item in result:
        if enabled and item["control"]:
            if item["status"] != FORBIDDEN:
                fail("DVWA WAF block missing")
        else:
            if item["status"] != SUCCESS or (
                "login.php" in item["body"] and "Logout" not in item["body"]
            ):
                fail("native authenticated DVWA response missing")
            if item["label"] == "sql" and item["body"].count("First name:") < MIN_ROWS:
                fail("SQL injection did not expose multiple synthetic rows")
            if item["label"] == "xss" and MARKER not in item["body"]:
                fail("reflected executable harmless marker missing")
            if (
                item["label"] == "legitimate-sql"
                and item["body"].count("First name:") != 1
            ):
                fail("legitimate DVWA row response missing")
            if (
                item["label"] == "legitimate-xss"
                and "Hello synthetic visitor" not in item["body"]
            ):
                fail("legitimate DVWA reflected greeting missing")
    return result


def browser_marker(client: Client, html: str, enabled: bool, directory: Path) -> dict:
    """Execute only the captured harmless response offline; never collect user data."""
    file = directory / ("after-marker.html" if enabled else "before-marker.html")
    file.write_text(html)
    file.chmod(0o600)
    script = """
const {chromium}=require('playwright');
(async()=>{const b=await chromium.launch({headless:true});try{
const p=await b.newPage();await p.route('**/*',r=>r.abort());
await p.setContent(require('fs').readFileSync(process.argv[1],'utf8'));
process.stdout.write(JSON.stringify({title:await p.title()}));
}finally{await b.close();}})().catch(()=>process.exit(2));
"""
    result = json.loads(client.command(["node", "-e", script, str(file)]))
    if (result.get("title") == "waap-synthetic-marker") == enabled:
        fail("harmless browser marker outcome mismatch")
    return result
