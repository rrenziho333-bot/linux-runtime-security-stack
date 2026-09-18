#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Please run this script with sudo." >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FALCO_CONFIG="/etc/falco/falco.yaml"
BACKUP_SUFFIX="$(date +%Y%m%d-%H%M%S)"

# Install a validated repository bundle without replacing package or host rules.
python3 "${SCRIPT_DIR}/manage_rules.py" install

# Ensure Falco writes JSON events to the file TSA watches (/var/log/falco/
# falco.json) AND that the file is readable by TSA's non-root user (adm group).
# Three things must line up across Falco versions:
#   1. json_output must be on, so Falco emits JSON events (not plain text).
#   2. file_output must point Falco at /var/log/falco/falco.json.
#   3. The file Falco creates must be group-readable (adm), since
#      falco-modern-bpf.service ships with UMask=0077 and runs as root, which
#      would produce 0600 root:root unreadable by the non-root tsa-fusion.
#
# We do #1/#2 via /etc/falco/config.d (the `config_files` Stable mechanism).
# The shape of `json_output` changed across versions: older Falco used a map
# (`json_output:\n  enabled: true`), Falco 0.44 flattened it to a scalar
# (`json_output: true`). Emitting the wrong shape silently fails to enable
# JSON output, so probe the installed falco.yaml and generate the matching
# form. #3 is a systemd drop-in overriding UMask/Group on the falco unit.
FALCO_OUT_DIR="/var/log/falco"
install -d -o root -g adm -m 2750 "${FALCO_OUT_DIR}"
# Create the stream before TSA starts; Falco may not open it until an alert.
FALCO_LOG="${FALCO_OUT_DIR}/falco.json"
if [[ -L ${FALCO_LOG} || ( -e ${FALCO_LOG} && ! -f ${FALCO_LOG} ) ]]; then
  echo "Falco output must be a regular file, not a symlink: ${FALCO_LOG}" >&2
  exit 1
fi
touch -- "${FALCO_LOG}"
chown root:adm -- "${FALCO_LOG}"
chmod 0640 -- "${FALCO_LOG}"
install -d -o root -g root -m 0755 /etc/falco/config.d

python3 - "${FALCO_CONFIG}" > /etc/falco/config.d/zz-security-stack-output.yaml <<'PY'
from pathlib import Path
import re
import sys
import yaml

cfg = Path(sys.argv[1]).read_text(encoding="utf-8")
document = yaml.safe_load(cfg) or {}
extra = list(document.get("append_output") or [])
# Preserve host output enrichment, including Falco's suggested container fields.
for item in document.get("config_files", []):
    path = Path(item["path"] if isinstance(item, dict) else item)
    strategy = item.get("strategy", "override") if isinstance(item, dict) else "override"
    files = sorted(path.glob("*.y*ml")) if path.is_dir() else [path]
    for file in files:
        if not file.is_file() or file.name == "zz-security-stack-output.yaml":
            continue
        settings = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        if "append_output" in settings:
            values = settings["append_output"] or []
            extra = extra + values if strategy == "append" else list(values)
extra.append({"match": {"source": "syscall"}, "extra_fields": [
    "proc.pid", "proc.exepath", "user.uid", "evt.type", "evt.is_open_write", "evt.rawres"]})

# Detect whether `json_output` is a scalar (Falco >= 0.44, e.g. "json_output:
# true") or a map (older Falco, "json_output:\n  enabled: true"). Emitting the
# wrong shape silently fails to enable JSON, so probe the installed file. Use
# [ \t] (not \s) so the anchor never crosses a newline.
scalar_on_line = re.search(r"(?m)^json_output:[ \t]*\S", cfg)
map_header = re.search(r"(?m)^json_output:[ \t]*$", cfg)
scalar_json = bool(scalar_on_line) or not map_header

lines = [
    "# Managed by deploy-host-falco.sh — make Falco emit JSON rule events to",
    "# the file TSA's fusion agent reads, with the right shape of json_output",
    "# for the installed Falco version.",
]
if scalar_json:
    lines += ["json_output: true"]
else:
    lines += ["json_output:", "  enabled: true"]
lines += [
    "file_output:",
    "  enabled: true",
    "  keep_alive: false",
    "  filename: /var/log/falco/falco.json",
]
sys.stdout.write("\n".join(lines) + "\n")
sys.stdout.write(yaml.safe_dump({"append_output": extra}, sort_keys=False))
PY
chmod 0644 /etc/falco/config.d/zz-security-stack-output.yaml

# 3. File permissions: the packaged falco-modern-bpf.service runs as root with
# UMask=0077, so file_output creates 0600 root:root files the non-root tsa-fusion
# (SupplementaryGroups=adm) cannot read. Two fixes:
#   - The /var/log/falco dir is created setgid (mode 2750) with group adm, so
#     files Falco creates inside inherit group adm.
#   - A drop-in overrides the unit's UMask (0007) so those files are 0640
#     (group-readable), without touching the packaged unit (upgrades safe).
# tsa-fusion runs with SupplementaryGroups=adm, so it can then read the file.
install -d -o root -g root -m 0755 /etc/systemd/system/falco-modern-bpf.service.d
cat > /etc/systemd/system/falco-modern-bpf.service.d/security-stack.conf <<'CONF'
# Managed by deploy-host-falco.sh — let tsa-fusion (adm group) read Falco's
# file_output JSON. Packaged unit uses UMask=0077 (files end up 0600 root:root).
[Service]
UMask=0007
CONF
chmod 0644 /etc/systemd/system/falco-modern-bpf.service.d/security-stack.conf
systemctl daemon-reload

falco --dry-run

if systemctl cat falco-logger.service >/dev/null 2>&1; then
  systemctl disable --now falco-logger.service
fi

# The earlier container deployment installed a real falco.service file. Falco's
# packaged modern eBPF unit declares falco.service as an alias, so the old file
# must be archived before systemd can create that alias.
LEGACY_FALCO_UNIT="/etc/systemd/system/falco.service"
if [[ -f ${LEGACY_FALCO_UNIT} && ! -L ${LEGACY_FALCO_UNIT} ]]; then
  systemctl disable --now falco.service || true
  cp --preserve=all \
    "${LEGACY_FALCO_UNIT}" \
    "${LEGACY_FALCO_UNIT}.container-backup-${BACKUP_SUFFIX}"
  rm -f "${LEGACY_FALCO_UNIT}"
  systemctl daemon-reload
fi

systemctl enable falco-modern-bpf.service
systemctl restart falco-modern-bpf.service

systemctl --no-pager --full status falco-modern-bpf.service
echo
echo "Host Falco deployment completed."
echo "Rules and original configuration backup: see the rule installer output above."
