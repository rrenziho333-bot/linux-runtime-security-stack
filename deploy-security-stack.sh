#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this script with sudo." >&2
  exit 1
fi

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GO_BIN="/usr/local/go/bin/go"
BUILD_USER="${SUDO_USER:-zhaoren}"
BUILD_HOME="$(getent passwd "${BUILD_USER}" | cut -d: -f6)"
BUILD_OUTPUT="${ROOT_DIR}/bpf-lsm-controller"
TSA_DIR="${ROOT_DIR}/tsa"
MAINTENANCE_DIR="/run/tsa-fusion"
MAINTENANCE_FILE="${MAINTENANCE_DIR}/maintenance"

if [[ ! -x ${GO_BIN} ]]; then
  echo "Required Go toolchain is missing: ${GO_BIN}" >&2
  exit 1
fi
if [[ -z ${BUILD_HOME} || ! -d ${BUILD_HOME} ]]; then
  echo "Cannot determine home directory for build user ${BUILD_USER}." >&2
  exit 1
fi

install -d -o root -g root -m 0755 "${MAINTENANCE_DIR}"
install -o root -g root -m 0644 /dev/null "${MAINTENANCE_FILE}"
cleanup_maintenance() {
  rm -f "${MAINTENANCE_FILE}"
}
trap cleanup_maintenance EXIT

# Reload the already-installed TSA process before build/deployment activity so
# it recognizes the maintenance marker using the current source code.
if systemctl cat tsa-fusion.service >/dev/null 2>&1; then
  systemctl restart tsa-fusion.service
fi

run_as_builder() {
  runuser -u "${BUILD_USER}" -- env \
    HOME="${BUILD_HOME}" \
    PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin" \
    GOTOOLCHAIN="auto" \
    GOPROXY="off" \
    "$@"
}

cd "${ROOT_DIR}"
run_as_builder "${GO_BIN}" version
run_as_builder "${GO_BIN}" test ./...
run_as_builder "${GO_BIN}" build -o "${BUILD_OUTPUT}" .
run_as_builder "${BUILD_OUTPUT}" -check -config "${ROOT_DIR}/policy.yaml"
runuser -u "${BUILD_USER}" -- sh -c \
  "cd '${TSA_DIR}' && python3 -m unittest discover -s tests -v"

"${ROOT_DIR}/falco/deploy-host-falco.sh"

install -D -o root -g root -m 0755 \
  "${BUILD_OUTPUT}" /usr/local/sbin/bpf-lsm-controller
install -D -o root -g root -m 0644 \
  "${ROOT_DIR}/policy.yaml" /etc/bpf-lsm/policy.yaml
install -D -o root -g root -m 0644 \
  "${ROOT_DIR}/systemd/bpf-lsm-controller.service" \
  /etc/systemd/system/bpf-lsm-controller.service
install -D -o root -g root -m 0644 \
  "${ROOT_DIR}/systemd/tsa-fusion.service" \
  /etc/systemd/system/tsa-fusion.service
install -D -o root -g root -m 0644 \
  "${ROOT_DIR}/systemd/tsa-dashboard.service" \
  /etc/systemd/system/tsa-dashboard.service
install -D -o root -g root -m 0644 \
  "${ROOT_DIR}/logrotate/bpf-lsm" /etc/logrotate.d/bpf-lsm
install -D -o root -g root -m 0644 \
  "${ROOT_DIR}/logrotate/falco-json" /etc/logrotate.d/falco-json

install -d -o root -g adm -m 0750 /var/log/bpf-lsm
install -d -o "${BUILD_USER}" -g "${BUILD_USER}" -m 0750 "${TSA_DIR}/state"
install -d -o "${BUILD_USER}" -g "${BUILD_USER}" -m 0750 "${TSA_DIR}/reports"

# Stop a temporary foreground dashboard used during development so the
# managed service can bind its loopback port cleanly.
pkill -u "${BUILD_USER}" -f \
  "^python3 ${TSA_DIR}/tsa_dashboard.py .*--port 8766$" || true

systemctl daemon-reload
systemctl enable bpf-lsm-controller.service
systemctl enable tsa-fusion.service
systemctl enable tsa-dashboard.service
systemctl restart bpf-lsm-controller.service
systemctl restart tsa-fusion.service
systemctl restart tsa-dashboard.service

systemctl --no-pager --full status bpf-lsm-controller.service
systemctl --no-pager --full status tsa-fusion.service
systemctl --no-pager --full status tsa-dashboard.service

echo
echo "Security stack deployed. BPF LSM policy mode remains AUDIT."
echo "Dashboard: http://127.0.0.1:8766/"
