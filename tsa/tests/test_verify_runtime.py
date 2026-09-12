import unittest
import contextlib
import errno
import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from verify_runtime import evaluate, write_demo


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.falco = {"source": "falco", "pid": 77, "file": "/etc/tsa-protected-demo"}
        self.bpf = {"source": "bpf_lsm", "pid": 77, "operation": "write", "action": "audit",
                    "result": 0, "device": 8, "inode": 9}

    def test_audit_requires_write_success_and_both_sources(self):
        attempt = {"pid": 77, "outcome": "written"}
        self.assertTrue(evaluate([self.falco, self.bpf], attempt, 8, 9, "audit")[0])
        for rows in ([], [self.falco], [self.bpf], [self.falco, {**self.bpf, "pid": 78}],
                     [self.falco, {**self.bpf, "inode": 10}], [self.falco, {**self.bpf, "result": -1}]):
            self.assertFalse(evaluate(rows, attempt, 8, 9, "audit")[0])
        self.assertFalse(evaluate([self.falco, self.bpf], {"pid": 77, "outcome": "error"}, 8, 9, "audit")[0])

    def test_deny_requires_actual_eperm_and_matching_kernel_evidence(self):
        event = {**self.bpf, "action": "deny", "result": -1}
        self.assertTrue(evaluate([event], {"pid": 77, "outcome": "denied"}, 8, 9, "deny")[0])
        self.assertFalse(evaluate([event], {"pid": 77, "outcome": "written"}, 8, 9, "deny")[0])

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
