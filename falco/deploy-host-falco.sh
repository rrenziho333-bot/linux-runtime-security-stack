#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Please run this script with sudo." >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
FALCO_CONFIG="/etc/falco/falco.yaml"
RULE_SOURCE_DIR="${SCRIPT_DIR}/rules.d"
BACKUP_SUFFIX="$(date +%Y%m%d-%H%M%S)"

if [[ ! -f ${FALCO_CONFIG} || ! -d ${RULE_SOURCE_DIR} ]]; then
  echo "Falco configuration or local rule source is missing." >&2
  exit 1
fi

cp --preserve=all "${FALCO_CONFIG}" "${FALCO_CONFIG}.bak-${BACKUP_SUFFIX}"
for rule_source in "${RULE_SOURCE_DIR}"/*.yaml; do
  rule_target="/etc/falco/rules.d/$(basename -- "${rule_source}")"
  install -D -o root -g root -m 0644 "${rule_source}" "${rule_target}"
done

python3 - "${FALCO_CONFIG}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = """rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco_rules.local.yaml
  - /etc/falco/rules.d
  - /etc/falco/falco-sandbox_rules.yaml
  - /etc/falco/falco-incubating_rules.yaml
"""
new = """rules_files:
  - /etc/falco/falco_rules.yaml
  - /etc/falco/falco-sandbox_rules.yaml
  - /etc/falco/falco-incubating_rules.yaml
  - /etc/falco/rules.d
  - /etc/falco/falco_rules.local.yaml
"""
if old in text:
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
elif new not in text:
    raise SystemExit("Unexpected rules_files block; configuration was not modified")
PY

falco -V /etc/falco/falco_rules.yaml \
  -V /etc/falco/falco-sandbox_rules.yaml \
  -V /etc/falco/falco-incubating_rules.yaml \
  -V /etc/falco/rules.d
falco --dry-run

systemctl disable --now falco-logger.service || true

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
echo "Backup: ${FALCO_CONFIG}.bak-${BACKUP_SUFFIX}"
