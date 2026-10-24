#!/usr/bin/env python3
"""Expire only stale anonymous sessions in the owned DVWA volume."""

import fcntl
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path

VOLUME = "origin-server_dvwa-sessions"
ROOT = "/var/lib/docker/volumes/" + VOLUME + "/_data"
RETENTION_SECONDS = 86400
MAX_SESSION_BYTES = 65536
MAX_REMOVALS = 25000


def cleanup(root: str, cutoff: float) -> dict:
    """Remove expired anonymous files, preserving recent and authenticated sessions."""
    removed = preserved = 0
    with os.scandir(root) as entries:
        for entry in entries:
            if not re.fullmatch(r"sess_[A-Za-z0-9,-]+", entry.name):
                continue
            before = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(before.st_mode) or before.st_mtime >= cutoff:
                continue
            # Authenticated sessions remain available for demonstrations and recovery.
            with Path(entry.path).open("rb") as stream:
                data = stream.read(MAX_SESSION_BYTES + 1)
            if len(data) > MAX_SESSION_BYTES or any(
                field in data
                for field in (b"logged_in|", b"user_id|", b"username|", b'"username"')
            ):
                preserved += 1
                continue
            after = entry.stat(follow_symlinks=False)
            if (before.st_ino, before.st_mtime_ns, before.st_size) == (
                after.st_ino,
                after.st_mtime_ns,
                after.st_size,
            ):
                Path(entry.path).unlink()
                removed += 1
                if removed >= MAX_REMOVALS:
                    break
    return {"removed": removed, "authenticated_preserved": preserved}


def main() -> None:
    """Prove volume ownership and serialize retention before touching sessions."""
    volume = json.loads(
        subprocess.check_output(["/usr/bin/docker", "volume", "inspect", VOLUME])  # noqa: S603 - fixed owned volume read
    )[0]
    if (
        volume["Name"] != VOLUME
        or volume["Mountpoint"] != ROOT
        or volume.get("Labels", {}).get("com.docker.compose.project") != "origin-server"
        or Path(ROOT).is_symlink()
    ):
        message = "DVWA session volume ownership mismatch"
        raise SystemExit(message)
    with Path("/run/lock/demo-dvwa-session-cleanup.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(cleanup(ROOT, time.time() - RETENTION_SECONDS)))


if __name__ == "__main__":
    main()
