#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 || -z ${SUDO_USER:-} || ${SUDO_USER} == root ]]; then
  echo "Run this script with sudo from an ordinary user account." >&2
  exit 1
fi
ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_USER="${SUDO_USER}"
if [[ ! ${ROOT_DIR} =~ ^/[a-zA-Z0-9_./-]+$ ]]; then
  echo "Use a checkout path containing only letters, digits, /, _, -, and ." >&2
  exit 1
fi
RUNTIME_GROUP="$(id -gn "${RUNTIME_USER}")"
TSA_DIR="${ROOT_DIR}/tsa"

install -d -o root -g root -m 0755 /run/tsa-fusion
install -o root -g root -m 0644 /dev/null /run/tsa-fusion/maintenance
trap 'rm -f /run/tsa-fusion/maintenance' EXIT

# Validate before changing the installed services.
cd "${TSA_DIR}"
runuser -u "${RUNTIME_USER}" -- python3 -m unittest discover -s tests -v
cd "${ROOT_DIR}"
python3 falco/manage_rules.py check
python3 - <<'PY'
import yaml
with open('tsa/policy_config.yaml', encoding='utf-8') as stream:
    baseline = yaml.safe_load(stream)['baseline_lynis']
if baseline.get('report_path') != '/var/lib/tsa-baseline/lynis-report.dat' or baseline.get('run_lynis'):
    raise SystemExit('Use baseline_lynis.report_path=/var/lib/tsa-baseline/lynis-report.dat and run_lynis=false for the managed scanner.')
PY

# Upgrade from the former enforcement stack. Preserve logs, databases and
# a root-only backup of installed components; stopping the service detaches LSM.
if systemctl cat bpf-lsm-controller.service >/dev/null 2>&1; then
  unit="$(systemctl cat bpf-lsm-controller.service)"
  if [[ ${unit} != *"/usr/local/sbin/bpf-lsm-controller"* ]]; then
    echo "Unrecognized legacy controller unit; inspect it before upgrading." >&2
    exit 1
  fi
  backup="$(mktemp -d /var/backups/lrss-legacy-XXXXXXXX)"
  for path in /etc/systemd/system/bpf-lsm-controller.service /usr/local/sbin/bpf-lsm-controller /etc/bpf-lsm/policy.yaml /etc/logrotate.d/bpf-lsm; do
    if [[ -e ${path} ]]; then
      cp -a --parents -- "${path}" "${backup}/"
    fi
  done
  systemctl disable --now bpf-lsm-controller.service
  if systemctl is-active --quiet bpf-lsm-controller.service; then
    echo "Legacy controller is still active; deployment stopped." >&2
    exit 1
  fi
  rm -f /etc/systemd/system/bpf-lsm-controller.service /usr/local/sbin/bpf-lsm-controller /etc/bpf-lsm/policy.yaml /etc/logrotate.d/bpf-lsm
  echo "Legacy controller removed; backup: ${backup}. Historical logs and databases retained."
fi

# The historical filename is a bounded alert test target, not a protected object.
if [[ ! -e /etc/tsa-protected-demo && ! -L /etc/tsa-protected-demo ]]; then
  install -o root -g root -m 0640 /dev/null /etc/tsa-protected-demo
fi
"${ROOT_DIR}/falco/deploy-host-falco.sh"
install -D -o root -g root -m 0644 "${ROOT_DIR}/logrotate/falco-json" /etc/logrotate.d/falco-json
install -d -o "${RUNTIME_USER}" -g "${RUNTIME_GROUP}" -m 0750 "${TSA_DIR}/state" "${TSA_DIR}/reports" "${TSA_DIR}/settings"

# Provision a root-only management credential once; never print or rotate it on upgrade.
install -d -o root -g root -m 0755 /etc/tsa
python3 - <<'PY'
import os
import secrets
import stat
from pathlib import Path
path = Path('/etc/tsa/weights-api.env')
if path.is_symlink():
    raise SystemExit('Refusing symlink management credential')
if path.exists():
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise SystemExit('Management credential must be a root-owned regular file with mode 0600')
else:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write('TSA_WEIGHTS_API_TOKEN=' + secrets.token_urlsafe(48) + '\nTSA_WEIGHTS_API_CLIENT=main-system\n')
PY

for service in tsa-fusion tsa-dashboard; do
  rendered="$(mktemp)"
  sed -e "s#__RUNTIME_USER__#${RUNTIME_USER}#g" \
      -e "s#__SRC_DIR__#${ROOT_DIR}#g" \
      "${ROOT_DIR}/systemd/${service}.service" >"${rendered}"
  if grep -q '__[A-Z_]*__' "${rendered}"; then
    rm -f "${rendered}"
    echo "Unresolved service placeholders." >&2
    exit 1
  fi
  install -D -o root -g root -m 0644 "${rendered}" "/etc/systemd/system/${service}.service"
  rm -f "${rendered}"
done
systemctl daemon-reload
install -d -o root -g adm -m 0750 /var/lib/tsa-baseline
install -D -o root -g root -m 0644 "${TSA_DIR}/refresh_baseline.py" /usr/local/libexec/tsa-refresh-baseline.py
for unit in tsa-baseline.service tsa-baseline.timer; do
  install -o root -g root -m 0644 "${ROOT_DIR}/systemd/${unit}" "/etc/systemd/system/${unit}"
done
systemctl daemon-reload
# Replace the package timer, which publishes a different report in /var/log.
if systemctl cat lynis.timer >/dev/null 2>&1; then
  systemctl disable --now lynis.timer
fi
echo "Generating baseline; this can take several minutes. See journalctl -fu tsa-baseline."
systemctl enable --now tsa-baseline.timer
systemctl start tsa-baseline.service
systemctl enable tsa-fusion.service tsa-dashboard.service
systemctl restart tsa-fusion.service tsa-dashboard.service
systemctl --no-pager --full status falco-modern-bpf.service tsa-fusion.service tsa-dashboard.service

echo "Detection-only stack deployed: Falco + Lynis + TSA. No blocking or process termination."
echo "Dashboard: http://127.0.0.1:8766/ (loopback only)"
echo "Risk score API: http://127.0.0.1:8766/systemManage/risk/score"
echo "Weight management API: /systemManage/risk/weights (credential: /etc/tsa/weights-api.env, root only)"
