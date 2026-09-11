#!/usr/bin/env python3
"""Extract only the three expected regular rule files from a release archive."""

import sys
import tarfile
from pathlib import Path, PurePosixPath


RULE_FILES = ("falco_rules.yaml", "falco-sandbox_rules.yaml", "falco-incubating_rules.yaml")
MAX_SIZE = 20 * 1024 * 1024


def extract_rules(archive: Path, destination: Path) -> None:
    selected = {}
    with tarfile.open(archive, "r:gz") as source:
        for count, member in enumerate(source):
            if count >= 1000 or member.size > MAX_SIZE:
                raise ValueError("Archive exceeds size or member limits")
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or member.issym() or member.islnk():
                raise ValueError("Archive contains unsafe paths or links")
            if name.name not in RULE_FILES:
                continue
            if not member.isfile() or member.size > MAX_SIZE or name.name in selected:
                raise ValueError("Invalid, oversized, or duplicate rule file")
            stream = source.extractfile(member)
            if stream is None:
                raise ValueError("Unreadable rule file")
            with stream:
                selected[name.name] = stream.read(MAX_SIZE + 1)
        if set(selected) != set(RULE_FILES):
            raise ValueError("Archive must contain all three official rule files")
    for name, content in selected.items():
        with (destination / name).open("xb") as output:
            output.write(content)


if __name__ == "__main__":
    extract_rules(Path(sys.argv[1]), Path(sys.argv[2]))
