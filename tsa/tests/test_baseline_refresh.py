import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from refresh_baseline import collect, publish, validate_report


COMPLETE = 'report_version_major=1\ntests_executed=PKGS-7392|\nreport_datetime_end=2026-09-20 12:00:00\nfinish=true\n'


class BaselineRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old = self.root / 'lynis-report.dat'
        self.old.write_text('old report', encoding='utf-8')

    def test_requires_completed_execution_metadata(self):
        for content in ('', COMPLETE.replace('finish=true', 'finish=false'),
                        COMPLETE.replace('tests_executed=PKGS-7392|', 'tests_executed='),
                        COMPLETE.replace('report_version_major=1', 'report_version_major=9')):
            self.old.write_text(content, encoding='utf-8')
            with self.assertRaises(ValueError):
                validate_report(self.old)
        self.old.write_text(COMPLETE, encoding='utf-8')
        validate_report(self.old)

    @unittest.skipUnless(os.name == 'posix', 'Linux file locking and atomic publication')
    def test_success_publishes_after_validation_only(self):
        def run(command, **kwargs):
            self.assertEqual(self.old.read_text(), 'old report')
            if '--report-file' in command:
                Path(command[command.index('--report-file') + 1]).write_text(COMPLETE)
        with patch('refresh_baseline.subprocess.run', side_effect=run) as execute, \
             patch('refresh_baseline.os.chown'):
            collect(self.root, 0)
        self.assertEqual(self.old.read_text(), COMPLETE)
        self.assertEqual(self.old.stat().st_mode & 0o777, 0o640)
        self.assertEqual(execute.call_count, 2)
        self.assertIn('APT::Update::Error-Mode=any', execute.call_args_list[0].args[0])
        self.assertFalse(list(self.root.glob('.scan-*')))

    @unittest.skipUnless(os.name == 'posix', 'Linux worker')
    def test_apt_failure_keeps_old_report_without_starting_lynis(self):
        with patch('refresh_baseline.subprocess.run', side_effect=subprocess.CalledProcessError(1, 'apt')) as execute:
            with self.assertRaises(subprocess.CalledProcessError):
                collect(self.root, 0)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(self.old.read_text(), 'old report')

    @unittest.skipUnless(os.name == 'posix', 'Linux worker')
    def test_incomplete_audit_keeps_old_report(self):
        def run(command, **kwargs):
            if '--report-file' in command:
                Path(command[command.index('--report-file') + 1]).write_text('finish=false\n')
        with patch('refresh_baseline.subprocess.run', side_effect=run):
            with self.assertRaises(ValueError):
                collect(self.root, 0)
        self.assertEqual(self.old.read_text(), 'old report')
        self.assertFalse(list(self.root.glob('.scan-*')))

    @unittest.skipUnless(os.name == 'posix', 'Linux worker')
    def test_lynis_failure_keeps_old_report(self):
        with patch('refresh_baseline.subprocess.run', side_effect=[None, subprocess.TimeoutExpired('lynis', 1800)]):
            with self.assertRaises(subprocess.TimeoutExpired):
                collect(self.root, 0)
        self.assertEqual(self.old.read_text(), 'old report')
        self.assertFalse(list(self.root.glob('.scan-*')))

    @unittest.skipUnless(os.name == 'posix', 'Linux symlinks')
    def test_rejects_symlink_destination(self):
        candidate = self.root / 'candidate'
        candidate.write_text(COMPLETE)
        link = self.root / 'link'
        link.symlink_to(self.old)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            publish(candidate, link, 0)
        self.assertEqual(self.old.read_text(), 'old report')

    @unittest.skipUnless(os.name == 'posix', 'Linux file locking')
    def test_concurrent_scan_does_not_start(self):
        import fcntl
        with (self.root / 'scan.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch('refresh_baseline.subprocess.run') as execute:
                with self.assertRaises(BlockingIOError):
                    collect(self.root, 0)
                execute.assert_not_called()
