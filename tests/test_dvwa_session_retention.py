# ruff: noqa: PT009
"""Session retention protects authentication, active files and unrelated entries."""

import os
import tempfile
import time
import unittest
from pathlib import Path

from dvwa_session_retention import cleanup


class SessionRetentionTests(unittest.TestCase):
    def test_only_expired_anonymous_sessions_are_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = time.time() - 90000
            cases = {
                "sess_anonymous": b'username_token|s:4:"test";',
                "sess_authenticated": b'dvwa|a:1:{s:8:"username";s:5:"admin";}',
                "sess_recent": b"",
                "unrelated": b"",
            }
            for name, data in cases.items():
                path = root / name
                path.write_bytes(data)
                if name != "sess_recent":
                    os.utime(path, (old, old))
            (root / "sess_directory").mkdir()
            (root / "sess_link").symlink_to(root / "unrelated")
            result = cleanup(str(root), time.time() - 86400)
            self.assertEqual(result, {"removed": 1, "authenticated_preserved": 1})
            self.assertFalse((root / "sess_anonymous").exists())
            self.assertTrue(
                all(
                    (root / name).exists() for name in cases if name != "sess_anonymous"
                )
            )
            self.assertTrue((root / "sess_link").is_symlink())
