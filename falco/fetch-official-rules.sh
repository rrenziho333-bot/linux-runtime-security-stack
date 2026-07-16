#!/usr/bin/env bash
# Mirror Falco's official rule sets into ./official-rules/ so they can be read
# and analysed directly from the repository. The deployed rules remain the ones
# shipped by the installed falco package (see deploy-host-falco.sh); this is a
# read-only copy for analysis, kept out of git.
#
# Strategy (in order, first success wins):
#   1. LOCAL: copy from the running falco install (default /etc/falco).
#      This is the most accurate — it is exactly the rule set that will be
#      deployed on this host. Recommended when falco is already installed.
#   2. REMOTE: download a release archive you point at with --remote-url.
#      Go to https://github.com/falcosecurity/rules/releases (or the falco
#      package release), copy the asset URL, and pass it here. The asset naming
#      differs across releases, so the URL is not hard-coded — you supply it.
#      Supports .tar.gz (archives are searched for the rule files) or a single
#      .yaml pointed at by --remote-url-file.
#
# Apache-2.0 licensed by falcosecurity.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEST_DIR="${SCRIPT_DIR}/official-rules"
FALCO_ETC="${FALCO_ETC:-/etc/falco}"
FILES=(falco_rules.yaml falco-sandbox_rules.yaml falco-incubating_rules.yaml)

usage() {
  cat >&2 <<EOF
Usage:
  $0                              # local copy from ${FALCO_ETC} (needs falco)
  $0 --remote-url <url>           # download a rules .tar.gz from <url>
  $0 --remote-url-file <url> <name>  # download a single yaml <name> from <url>
  FALCO_ETC=/path $0              # non-default falco install dir
Examples:
  $0 --remote-url https://github.com/falcosecurity/rules/releases/download/0.8.0/falco_rules.tar.gz
EOF
  exit 1
}

MODE="local"
REMOTE_URL=""
REMOTE_FILE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --remote-url) MODE="remote-tar"; shift
                  [[ $# -eq 0 ]] && usage; REMOTE_URL="$1"; shift ;;
    --remote-url-file) MODE="remote-yaml"; shift
                  [[ $# -eq 0 ]] && usage; REMOTE_URL="$1"; shift
                  [[ $# -eq 0 ]] && usage; REMOTE_FILE="$1"; shift ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

mkdir -p "${DEST_DIR}"

copy_local() {
  if [[ ! -d ${FALCO_ETC} ]]; then
    echo "No falco install found at ${FALCO_ETC}." >&2
    return 1
  fi
  local missing=0
  for f in "${FILES[@]}"; do
    [[ -f "${FALCO_ETC}/${f}" ]] || { echo "Missing ${FALCO_ETC}/${f}" >&2; missing=1; }
  done
  [[ ${missing} -eq 0 ]] || return 1
  echo "Copying official rules from local falco install (${FALCO_ETC}):"
  for f in "${FILES[@]}"; do
    echo "  ${FALCO_ETC}/${f}"
    cp -f "${FALCO_ETC}/${f}" "${DEST_DIR}/${f}"
  done
  local ver
  ver="$(falco --version 2>/dev/null | awk '{print $NF}' || echo unknown)"
  write_version "local:${ver}"
}

fetch_remote_tar() {
  [[ -n ${REMOTE_URL} ]] || usage
  local tmpdir tarball
  tmpdir="$(mktemp -d)"
  tarball="${tmpdir}/rules.tar.gz"
  echo "Downloading ${REMOTE_URL}"
  if ! curl -fsSL "${REMOTE_URL}" -o "${tarball}"; then
    echo "Download failed. Verify the URL points to a .tar.gz asset." >&2
    rm -rf "${tmpdir}"
    exit 1
  fi
  tar -xzf "${tarball}" -C "${tmpdir}"
  echo "Extracting official rules:"
  for f in "${FILES[@]}"; do
    local src
    src="$(find "${tmpdir}" -type f -name "${f}" | head -1)"
    if [[ -z ${src} ]]; then
      echo "  ${f} not found in archive" >&2
      rm -rf "${tmpdir}"
      exit 1
    fi
    echo "  ${f}"
    cp -f "${src}" "${DEST_DIR}/${f}"
  done
  rm -rf "${tmpdir}"
  write_version "remote-tar:${REMOTE_URL}"
}

fetch_remote_yaml() {
  [[ -n ${REMOTE_URL} && -n ${REMOTE_FILE} ]] || usage
  echo "Downloading ${REMOTE_FILE} from ${REMOTE_URL}"
  if ! curl -fsSL "${REMOTE_URL}" -o "${DEST_DIR}/${REMOTE_FILE}"; then
    echo "Download failed for ${REMOTE_URL}" >&2
    exit 1
  fi
  write_version "remote-yaml:${REMOTE_URL}"
}

write_version() {
  local source="$1"
  cat >"${DEST_DIR}/VERSION.txt" <<EOF
source=${source}
fetched_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
files=${FILES[*]}
This directory mirrors Falco's official rules for offline analysis only.
The deployed rules remain those shipped by the installed falco package.
EOF
}

if [[ ${MODE} == "local" ]]; then
  copy_local || { echo "Falco not installed locally; use --remote-url <tarball-url>." >&2; exit 1; }
elif [[ ${MODE} == "remote-tar" ]]; then
  fetch_remote_tar
else
  fetch_remote_yaml
fi

echo
echo "Done. ${#FILES[@]} files in ${DEST_DIR}/"
echo "Analyse with, e.g.: grep -c '^- rule:' ${DEST_DIR}/falco_rules.yaml"