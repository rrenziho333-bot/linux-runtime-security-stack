import unittest
import contextlib
import errno
import io
import json
import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from verify_runtime import evaluate, main, write_demo


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.falco = {"source": "falco", "pid": 77, "file": "/etc/tsa-protected-demo",
                      "syscall": "openat", "is_open_write": True}

    def test_detection_requires_successful_write_and_matching_falco_evidence(self):
        attempt = {"pid": 77, "outcome": "written"}
        self.assertTrue(evaluate([self.falco], attempt)[0])
        for rows in ([], [{**self.falco, "pid": 78}], [{**self.falco, "file": "/etc/other"}],
                     [{**self.falco, "is_open_write": False}],
                     [{**self.falco, "source": "bpf_lsm"}]):
            self.assertFalse(evaluate(rows, attempt)[0])
        for outcome in ("error", "denied"):
            self.assertFalse(evaluate([self.falco], {"pid": 77, "outcome": outcome})[0])

    @unittest.skipUnless(os.name == "posix", "Ubuntu verification entry point")
    def test_sudo_failure_explains_cause_without_reporting_success(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "demo"
            target.write_text("original")
            data = MagicMock()
            data._connect.return_value.execute.return_value.fetchone.return_value = (0,)
            output = io.StringIO()
            error = subprocess.CalledProcessError(1, ["sudo"], stderr="sudo: a terminal is required")
            with patch("verify_runtime.TARGET", target), patch("verify_runtime.DashboardData", return_value=data), \
                    patch("verify_runtime.subprocess.run", side_effect=error), \
                    patch("sys.argv", ["verify_runtime.py"]), contextlib.redirect_stdout(output):
                self.assertEqual(main(), 1)
            self.assertIn("sudo: a terminal is required", output.getvalue())
            self.assertNotIn("PASS", output.getvalue())
            self.assertEqual(target.read_text(), "original")

    @unittest.skipUnless(os.name == "posix", "Linux file flags")
    def test_denied_write_is_not_retried_by_a_buffered_stream(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "demo"
            target.write_text("original")
            info = target.stat()
            output = io.StringIO()
            with patch("verify_runtime.TARGET", target), patch("verify_runtime.os.write", side_effect=PermissionError(errno.EPERM, "denied")) as write, contextlib.redirect_stdout(output):
                write_demo("token", info.st_dev, info.st_ino)
            self.assertEqual(json.loads(output.getvalue())["outcome"], "denied")
            self.assertEqual(write.call_count, 1)
            self.assertEqual(target.read_text(), "original")

    @unittest.skipUnless(os.name == "posix", "Linux file flags")
    def test_writer_refuses_changed_inode_and_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "demo"
            target.write_text("original")
            info = target.stat()
            with patch("verify_runtime.TARGET", target), contextlib.redirect_stdout(io.StringIO()):
                write_demo("token", info.st_dev, info.st_ino + 1)
            link = Path(folder) / "link"
            link.symlink_to(target)
            with patch("verify_runtime.TARGET", link), contextlib.redirect_stdout(io.StringIO()):
                write_demo("token", info.st_dev, info.st_ino)
            self.assertEqual(target.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
