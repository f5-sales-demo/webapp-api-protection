"""Verify installed system package identities against the Terraform artifact lock."""

import json
import shlex
from pathlib import Path

from demo_lifecycle_runtime import Runtime
from demo_lifecycle_state import Blocked

PACKAGE_CHECK = """import json,subprocess,sys
records=json.load(sys.stdin)
failures=[]
for record in records:
    result=subprocess.run(['/usr/bin/dpkg-query','-W','-f=${Version}\t${Architecture}\t${Status}',record['package']],capture_output=True,text=True,check=False)
    expected=[record['version'],record['architecture'],'install ok installed']
    if result.returncode or result.stdout.split(chr(9)) != expected:
        failures.append(record['package'])
print(json.dumps({'verified':not failures,'checked':len(records),'failures':failures}))
"""


PACKAGE_SCHEMA_VERSION = 2


def package_records(manifest: dict, role: str) -> list:
    """Resolve role references to unique canonical package artifacts."""
    message = "invalid canonical system package ownership lock"
    try:
        artifacts = {item["sha256"]: item for item in manifest["packages"]}
        references = manifest["dependency_roles"][role]
        records = [artifacts[key] for key in references]
        valid = (
            manifest["schema_version"] == PACKAGE_SCHEMA_VERSION
            and len(artifacts) == len(manifest["packages"])
            and bool(references)
            and len(set(references)) == len(references)
            and len({item["package"] for item in records}) == len(records)
        )
    except (KeyError, TypeError) as error:
        raise Blocked(message) from error
    if not valid:
        raise Blocked(message)
    return records


def verify_package_pins(runtime: Runtime, ssh: list, app: Path, role: str) -> None:
    """Reject absent or changed native package readback before guest acceptance."""
    manifest = json.loads((app / "ubuntu-packages.json").read_text())
    package_role = "origin-server" if role == "origin" else "traffic-generator"
    records = package_records(manifest, package_role)
    raw, _ = runtime.run(
        [*ssh, "sudo -n python3 -c " + shlex.quote(PACKAGE_CHECK)],
        input_text=json.dumps(records),
    )
    result = json.loads(raw)
    if result.get("verified") is not True or result.get("checked") != len(records):
        message = "installed " + role + " system packages differ from Terraform pins"
        raise Blocked(message)
