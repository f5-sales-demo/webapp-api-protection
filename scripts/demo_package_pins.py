"""Verify installed system package versions against the Terraform artifact lock."""

import json
import shlex
from pathlib import Path

from demo_lifecycle_runtime import Runtime
from demo_lifecycle_state import Blocked

PACKAGE_CHECK = """import json,subprocess,sys
records=json.load(sys.stdin)
failures=[]
for record in records:
    result=subprocess.run(['/usr/bin/dpkg-query','-W','-f=${Version}',record['package']],capture_output=True,text=True,check=False)
    if result.returncode or result.stdout != record['version']:
        failures.append(record['package'])
print(json.dumps({'verified':not failures,'checked':len(records),'failures':failures}))
"""


def verify_package_pins(runtime: Runtime, ssh: list, app: Path, role: str) -> None:
    """Reject absent or changed native package readback before guest acceptance."""
    manifest = json.loads((app / "ubuntu-packages.json").read_text())
    package_role = "origin-server" if role == "origin" else "traffic-generator"
    records = manifest["roles"][package_role]
    raw, _ = runtime.run(
        [*ssh, "sudo -n python3 -c " + shlex.quote(PACKAGE_CHECK)],
        input_text=json.dumps(records),
    )
    result = json.loads(raw)
    if result.get("verified") is not True or result.get("checked") != len(records):
        message = "installed " + role + " system packages differ from Terraform pins"
        raise Blocked(message)
