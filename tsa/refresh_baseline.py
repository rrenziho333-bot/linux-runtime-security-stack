#!/usr/bin/env python3
"""Root-owned systemd worker: publish only a complete, newly generated audit."""

import os
from pathlib import Path
import stat
import subprocess
import tempfile


DIRECTORY = Path('/var/lib/tsa-baseline')
REPORT = 'lynis-report.dat'


def validate_report(path):
    fields = {}
    for line in path.read_text(encoding='utf-8', errors='strict').splitlines():
        key, sep, value = line.partition('=')
        if sep:
            fields[key] = value
    if fields.get('report_version_major') != '1' or fields.get('finish') != 'true':
        raise ValueError('Lynis did not produce a complete version-1 report')
    if not fields.get('tests_executed', '').strip('|') or not fields.get('report_datetime_end'):
        raise ValueError('Lynis report has no execution metadata or completion time')


def publish(candidate, destination, gid):
    validate_report(candidate)
    # The parent is root-owned and not writable by the reader. Never follow an
    # existing destination symlink, even though os.replace would replace it.
    if destination.is_symlink():
        raise ValueError('Refusing symlink report destination')
    os.chown(candidate, 0, gid)
    os.chmod(candidate, 0o640)
    with candidate.open('rb') as stream:
        os.fsync(stream.fileno())
    os.replace(candidate, destination)
    fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def collect(directory, gid):
    import fcntl
    fd = os.open(directory / 'scan.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # apt-check relies on fresh indexes. Never turn a failed refresh into
        # an apparently current security baseline.
        subprocess.run(['/usr/bin/apt-get', '-o', 'APT::Update::Error-Mode=any',
                        '-o', 'Acquire::Retries=2', '-o', 'Acquire::http::Timeout=30',
                        '-o', 'Acquire::https::Timeout=30', 'update'], check=True, timeout=600)
        with tempfile.TemporaryDirectory(prefix='.scan-', dir=directory) as temporary:
            candidate = Path(temporary) / REPORT
            subprocess.run(['/usr/sbin/lynis', 'audit', 'system', '--quick', '--quiet',
                            '--report-file', str(candidate), '--logfile', str(directory / 'lynis.log')],
                           check=True, timeout=1800)
            publish(candidate, directory / REPORT, gid)
    print(f'Published complete Lynis report: {directory / REPORT}', flush=True)


def refresh(directory=DIRECTORY):
    import grp

    if os.geteuid() != 0:
        raise PermissionError('Run via sudo systemctl start tsa-baseline.service')
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('Baseline directory must be root-owned and not group/world writable')
    collect(directory, grp.getgrnam('adm').gr_gid)


if __name__ == '__main__':
    refresh()
