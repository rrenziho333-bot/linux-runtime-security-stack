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
install -d -o "${RUNTIME_USER}" -g "${RUNTIME_GROUP}" -m 0750 "${TSA_DIR}/state" "${TSA_DIR}/reports"

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
systemctl enable tsa-fusion.service tsa-dashboard.service
systemctl restart tsa-fusion.service tsa-dashboard.service
systemctl --no-pager --full status falco-modern-bpf.service tsa-fusion.service tsa-dashboard.service

echo "Detection-only stack deployed: Falco + Lynis + TSA. No blocking or process termination."
echo "Dashboard: http://127.0.0.1:8766/ (loopback only)"
echo "Risk score API: http://127.0.0.1:8766/systemManage/risk/score"
