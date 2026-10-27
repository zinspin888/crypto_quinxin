#!/usr/bin/env python3
"""The manual launcher must not clone the upstream behind bootstrap's back."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class LauncherGuardTests(unittest.TestCase):
    def test_missing_repo_is_not_cloned(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "absent")
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "php2shell_rce.py"),
                 "-u", "http://127.0.0.1:1/index.php", "-c", "id",
                 "--zif-offset", "0x1", "--dtor-offset", "0x2",
                 "--repo-dir", repo],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 4)
            self.assertFalse(os.path.exists(repo))
            self.assertIn("bootstrap_upstream.py", result.stderr)


if __name__ == "__main__":
    unittest.main()
