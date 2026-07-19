#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this script with sudo." >&2
  exit 1
fi

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
GO_BIN="/usr/local/go/bin/go"
if [[ -z ${SUDO_USER} ]]; then
  echo "Could not determine the runtime user: SUDO_USER is unset." >&2
  echo "Run this script with: sudo ${0}" >&2
  exit 1
fi
BUILD_USER="${SUDO_USER}"
RUNTIME_USER="${SUDO_USER}"
BUILD_HOME="$(getent passwd "${BUILD_USER}" | cut -d: -f6)"
BUILD_OUTPUT="${ROOT_DIR}/bpf-lsm-controller"
TSA_DIR="${ROOT_DIR}/tsa"
MAINTENANCE_DIR="/run/tsa-fusion"
MAINTENANCE_FILE="${MAINTENANCE_DIR}/maintenance"

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

# Render a template systemd unit (with __RUNTIME_USER__ / __SRC_DIR__
# placeholders) into a temporary file using the actual runtime user and
# project directory. The caller installs the returned temporary file.
render_unit() {
  local source_unit="$1"
  local rendered
  rendered="$(mktemp)"
  sed \
    -e "s#__RUNTIME_USER__#${RUNTIME_USER}#g" \
    -e "s#__SRC_DIR__#${ROOT_DIR}#g" \
    "${source_unit}" >"${rendered}"
  if grep -q '__[A-Z_]*__' "${rendered}"; then
    rm -f "${rendered}"
    echo "Rendering ${source_unit} left unresolved placeholders." >&2
    exit 1
  fi
  printf '%s' "${rendered}"
}

# Open the dashboard port (8766) so other hosts can reach the score API and
# dashboard. Best-effort: silently no-op if neither firewalld nor ufw is present.
DASHBOARD_PORT=8766
open_dashboard_port() {
  if systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --add-port="${DASHBOARD_PORT}/tcp" --permanent >/dev/null 2>&1 \
      && firewall-cmd --reload >/dev/null 2>&1 \
      && echo "Opened ${DASHBOARD_PORT}/tcp in firewalld."
    return
  fi
  if command -v ufw >/dev/null 2>&1 && ufw status >/dev/null 2>&1; then
    ufw allow "${DASHBOARD_PORT}/tcp" >/dev/null 2>&1 \
      && echo "Opened ${DASHBOARD_PORT}/tcp in ufw."
    return
  fi
  echo "No firewalld/ufw detected; ensure ${DASHBOARD_PORT}/tcp is reachable manually if needed."
}

# Detect whether the running kernel supports BPF LSM. Falco's modern eBPF
# driver (tracepoint/kprobe) does NOT require BPF LSM and still works when this
# returns false; only bpf-lsm-controller's kernel-level enforcement needs it.
bpf_lsm_available() {
  [[ -r /sys/kernel/security/lsm ]] || return 1
  grep -qw bpf /sys/kernel/security/lsm || return 1
  return 0
}

if bpf_lsm_available; then
  BPF_LSM_AVAILABLE=1
else
  BPF_LSM_AVAILABLE=0
fi

cd "${ROOT_DIR}"

# Ensure the demo protected object exists on fresh machines. In full mode the
# controller stats each policy path at startup (missing file aborts -check);
# create it up front either way so a later switch to full mode needs no prep.
DEMO_FILE="/etc/tsa-protected-demo"
if [[ ! -e ${DEMO_FILE} ]]; then
  install -o root -g root -m 0640 /dev/null "${DEMO_FILE}"
  echo "Created demo protected file ${DEMO_FILE}."
fi

if [[ ${BPF_LSM_AVAILABLE} -eq 1 ]]; then
  # Full mode: Go toolchain is required to build the bpf-lsm-controller binary.
  if [[ ! -x ${GO_BIN} ]]; then
    echo "Full mode needs the Go toolchain at ${GO_BIN} (install Go 1.23, see docs/INSTALL.md §3)." >&2
    exit 1
  fi
  run_as_builder "${GO_BIN}" test ./...
  run_as_builder "${GO_BIN}" build -o "${BUILD_OUTPUT}" .
  run_as_builder "${BUILD_OUTPUT}" -check -config "${ROOT_DIR}/policy.yaml"
else
  echo "Detection-only mode: skipping Go build and BPF controller (no Go needed)."
fi

# TSA is Python only; its tests run in both modes.
runuser -u "${BUILD_USER}" -- sh -c \
  "cd '${TSA_DIR}' && python3 -m unittest discover -s tests -v"

"${ROOT_DIR}/falco/deploy-host-falco.sh"

install -D -o root -g root -m 0644 \
  "${ROOT_DIR}/logrotate/falco-json" /etc/logrotate.d/falco-json

install -d -o "${BUILD_USER}" -g "${BUILD_USER}" -m 0750 "${TSA_DIR}/state"
install -d -o "${BUILD_USER}" -g "${BUILD_USER}" -m 0750 "${TSA_DIR}/reports"

if [[ ${BPF_LSM_AVAILABLE} -eq 1 ]]; then
  install -D -o root -g root -m 0755 \
    "${BUILD_OUTPUT}" /usr/local/sbin/bpf-lsm-controller
  install -D -o root -g root -m 0644 \
    "${ROOT_DIR}/policy.yaml" /etc/bpf-lsm/policy.yaml
  rendered_bpf_controller="$(render_unit "${ROOT_DIR}/systemd/bpf-lsm-controller.service")"
  install -D -o root -g root -m 0644 \
    "${rendered_bpf_controller}" /etc/systemd/system/bpf-lsm-controller.service
  rm -f "${rendered_bpf_controller}"
  install -D -o root -g root -m 0644 \
    "${ROOT_DIR}/logrotate/bpf-lsm" /etc/logrotate.d/bpf-lsm
  install -d -o root -g adm -m 0750 /var/log/bpf-lsm
else
  # Degraded mode: kernel has no BPF LSM. Keep the controller from being
  # installed/enabled, and tell TSA not to watch the (non-existent) BPF event
  # log so the fusion pipeline runs on Falco only.
  echo "BPF LSM not available on this kernel — deploying in detection-only mode."
  echo "  (bpf-lsm-controller is skipped; Falco + TSA + dashboard remain active.)"
  if grep -q '^bpf_lsm:' "${TSA_DIR}/policy_config.yaml"; then
    awk 'prev=="bpf_lsm:" && $0~/^[[:space:]]*enabled: true[[:space:]]*$/ \
           {$0="  enabled: false"} {prev=$1; print}' \
      "${TSA_DIR}/policy_config.yaml" > "${TSA_DIR}/policy_config.yaml.tmp" \
      && mv "${TSA_DIR}/policy_config.yaml.tmp" "${TSA_DIR}/policy_config.yaml"
  fi
fi

rendered_tsa_fusion="$(render_unit "${ROOT_DIR}/systemd/tsa-fusion.service")"
install -D -o root -g root -m 0644 \
  "${rendered_tsa_fusion}" /etc/systemd/system/tsa-fusion.service
rm -f "${rendered_tsa_fusion}"
rendered_tsa_dashboard="$(render_unit "${ROOT_DIR}/systemd/tsa-dashboard.service")"
install -D -o root -g root -m 0644 \
  "${rendered_tsa_dashboard}" /etc/systemd/system/tsa-dashboard.service
rm -f "${rendered_tsa_dashboard}"

# Stop a temporary foreground dashboard used during development so the
# managed service can bind its loopback port cleanly.
pkill -u "${BUILD_USER}" -f \
  "^python3 ${TSA_DIR}/tsa_dashboard.py .*--port 8766$" || true

systemctl daemon-reload
# Let other hosts reach the dashboard / score API (binds 0.0.0.0:8766).
open_dashboard_port
if [[ ${BPF_LSM_AVAILABLE} -eq 1 ]]; then
  systemctl enable bpf-lsm-controller.service
  systemctl restart bpf-lsm-controller.service
fi
systemctl enable tsa-fusion.service
systemctl enable tsa-dashboard.service
systemctl restart tsa-fusion.service
systemctl restart tsa-dashboard.service

if [[ ${BPF_LSM_AVAILABLE} -eq 1 ]]; then
  systemctl --no-pager --full status bpf-lsm-controller.service
fi
systemctl --no-pager --full status tsa-fusion.service
systemctl --no-pager --full status tsa-dashboard.service

echo
if [[ ${BPF_LSM_AVAILABLE} -eq 1 ]]; then
  echo "Security stack deployed. BPF LSM policy mode remains AUDIT."
else
  echo "Security stack deployed in DETECTION-ONLY mode (no BPF LSM enforcement)."
fi
echo "Dashboard: http://127.0.0.1:8766/  (other hosts: http://<this-host-ip>:8766/)"
echo "Risk score API:  GET http://<this-host-ip>:8766/systemManage/risk/score"
