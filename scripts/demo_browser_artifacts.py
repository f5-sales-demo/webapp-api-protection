"""Download and verify exact native browser artifacts and installed cache content."""

import argparse
import hashlib
import json
import stat
import urllib.request
import zipfile
from pathlib import Path


def prepare(record: dict, directory: Path) -> Path:
    """Verify archive bytes before publishing a reusable native browser artifact."""
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (record["sha256"] + ".zip")
    if not path.exists():
        temporary = path.with_suffix(".partial")
        digest = hashlib.sha256()
        size = 0
        with (
            urllib.request.urlopen(  # noqa: S310 -- immutable HTTPS artifact
                record["url"], timeout=180
            ) as response,
            temporary.open("wb") as output,
        ):
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
                digest.update(chunk)
                size += len(chunk)
        if size != record["bytes"] or digest.hexdigest() != record["sha256"]:
            message = "browser artifact bytes differ from declared ownership"
            raise ValueError(message)
        temporary.replace(path)
    if (
        path.stat().st_size != record["bytes"]
        or hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]
    ):
        message = "retained browser artifact bytes differ from declared ownership"
        raise ValueError(message)
    return path


def verify(record: dict, archive: Path) -> int:
    """Reject installed browser content or executable-mode drift."""
    checked = 0
    with zipfile.ZipFile(archive) as source:
        for item in source.infolist():
            relative = Path(item.filename)
            if relative.is_absolute() or ".." in relative.parts:
                message = "browser archive contains an invalid path"
                raise ValueError(message)
            if item.is_dir():
                continue
            installed = Path(record["cache_path"]) / relative
            mode = (item.external_attr >> 16) & 0o777
            valid = (
                not installed.is_symlink()
                and installed.is_file()
                and hashlib.sha256(installed.read_bytes()).digest()
                == hashlib.sha256(source.read(item)).digest()
                and stat.S_IMODE(installed.stat().st_mode) == mode
            )
            if not valid:
                message = "installed browser content differs from declared artifact"
                raise ValueError(message)
            checked += 1
    return checked


def main() -> None:
    """Verify every declared archive before installation or full cache readback."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "verify"))
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--archives", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.lock.read_text())
    results = []
    for record in manifest["artifacts"]:
        archive = prepare(record, args.archives)
        checked = verify(record, archive) if args.operation == "verify" else 0
        results.append(
            {
                "name": record["name"],
                "sha256": record["sha256"],
                "files_checked": checked,
            }
        )
    print(
        json.dumps(
            {"operation": args.operation, "verified": True, "artifacts": results}
        )
    )


if __name__ == "__main__":
    main()
