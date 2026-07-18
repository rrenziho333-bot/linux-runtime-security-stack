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

# The 95-security-stack-exceptions.yaml file appends two well-known official
# Falco symbols (list bpf_profiled_binaries, macro user_known_write_below_root_
# activities). Those symbols exist in some Falco releases and were removed in
# others (e.g. 0.44.x dropped both). append-style entries point at a symbol
# that does not exist is a hard load error for Falco, so we strip any block in
# the deployed 95 file whose "- list:" / "- macro:" name is absent from the
# official rule files that will actually be loaded. This keeps the whitelist
# effective on versions that provide the symbols and harmless on versions that
# don't, instead of breaking deployment.
EXCEPTIONS_FILE="/etc/falco/rules.d/95-security-stack-exceptions.yaml"
if [[ -f ${EXCEPTIONS_FILE} ]]; then
  OFFICIAL_FILES=()
  for f in \
    /etc/falco/falco_rules.yaml \
    /etc/falco/falco-sandbox_rules.yaml \
    /etc/falco/falco-incubating_rules.yaml; do
    [[ -f ${f} ]] && OFFICIAL_FILES+=("${f}")
  done
  python3 - "${EXCEPTIONS_FILE}" "${OFFICIAL_FILES[@]}" <<'PY'
from pathlib import Path
import re
import sys

exc_path = Path(sys.argv[1])
official_paths = [Path(p) for p in sys.argv[2:]]
official_text = "\n".join(p.read_text(encoding="utf-8") for p in official_paths)
lines = exc_path.read_text(encoding="utf-8").splitlines(keepends=True)

# A "- list:" / "- macro:" / "- rule:" line at column 0 opens a top-level
# block that absorbs following indented/blank lines until the next column-0
# opener. We keep a list/macro block only if the named symbol also exists in
# the official rules; an append block pointing at a symbol Falco removed makes
# `falco --dry-run` abort with "no list/macro by that name". Comments and
# rules are always kept.
TOPLEVEL = re.compile(r"^- (list|macro|rule): (\S+)")
kept = []
buf = []
buf_name = None
dropped = []

def symbol_exists(name):
    pat = re.compile(r"(?m)^- (?:list|macro): " + re.escape(name) + r"\s*$")
    return bool(pat.search(official_text))

for line in lines:
    m = TOPLEVEL.match(line)
    if m:
        if buf_name is None:
            kept.extend(buf)
        elif symbol_exists(buf_name):
            kept.extend(buf)
        else:
            dropped.append(buf_name)
        buf = [line]
        buf_name = m.group(2)
    else:
        buf.append(line)
# Flush the final block.
if buf_name is None:
    kept.extend(buf)
elif symbol_exists(buf_name):
    kept.extend(buf)
else:
    dropped.append(buf_name)

if dropped:
    exc_path.write_text("".join(kept), encoding="utf-8")
    print("Stripped 95-exceptions blocks whose official symbol is missing: "
          + ", ".join(dropped), file=sys.stderr)
PY
fi

python3 - "${FALCO_CONFIG}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

# Rebuild the rules_files block to load files in the order the security stack
# expects: core official rules first, then sandbox/incubating, then our custom
# rules.d (so they can override), then the local overrides file. Only include a
# file that actually exists on disk; new Falco releases ship a default
# falco.yaml whose rules_files omits sandbox/incubating, and we must not point
# Falco at a missing file (falco --dry-run would reject it). We also coerce any
# existing rules_files block into this canonical form rather than pattern-match
# a specific historical layout, so the script is robust across Falco versions.
desired = [
    "/etc/falco/falco_rules.yaml",
    "/etc/falco/falco-sandbox_rules.yaml",
    "/etc/falco/falco-incubating_rules.yaml",
    "/etc/falco/rules.d",
    "/etc/falco/falco_rules.local.yaml",
]
ordered = [p for p in desired if p == "/etc/falco/rules.d" or Path(p).is_file()]
new_block = "rules_files:\n" + "".join(f"  - {p}\n" for p in ordered)

# Match the existing rules_files block: the header line plus every following
# "  - ..." entry, stopping at the next top-level key or non-list content.
pattern = re.compile(
    r"(?m)^rules_files:\n(?:[ \t]*-[ \t]\S.*\n)+",
)
match = pattern.search(text)
if match and match.group(0) == new_block:
    # Already in the desired shape; nothing to write.
    pass
elif match:
    text = text[: match.start()] + new_block + text[match.end():]
    path.write_text(text, encoding="utf-8")
else:
    # No rules_files block found at all; fail loudly rather than guess.
    raise SystemExit("rules_files block not found in falco.yaml; configuration was not modified")
PY

# Only validate rule files that exist; a given Falco release may not ship
# sandbox/incubating rules, so we must not point `falco -V` at missing files.
function _falco_validate_existing() {
  local -a args=()
  for f in \
    /etc/falco/falco_rules.yaml \
    /etc/falco/falco-sandbox_rules.yaml \
    /etc/falco/falco-incubating_rules.yaml \
    /etc/falco/rules.d; do
    if [[ -e ${f} ]]; then
      args+=(-V "${f}")
    fi
  done
  if ((${#args[@]})); then
    falco "${args[@]}"
  else
    echo "No Falco rule files found to validate." >&2
    exit 1
  fi
}
_falco_validate_existing
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
