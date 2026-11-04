#!/usr/bin/env bash
# Controlled PyPI integration test.
# Creates two isolated environments with vulnerable/fixed demo package versions,
# runs a process from the vulnerable venv, then collects evidence and validates resolver output.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$ROOT/build"
VULN_VENV="/opt/python-vulnerable/.venv"
FIXED_VENV="/opt/python-fixed/.venv"
PACKAGE="${PYPI_TEST_PACKAGE:-demo-pkg}"
VULN_VERSION="${PYPI_VULN_VERSION:-1.0.0}"
FIXED_VERSION="${PYPI_FIXED_VERSION:-2.0.0}"
CVE_ID="${PYPI_TEST_CVE:-CVE-2024-DEMO}"
OSV_ID="${PYPI_TEST_OSV:-GHSA-demo}"

log() { printf '[pypi-test] %s\n' "$*"; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "Run as root on the Ubuntu test host" >&2
    exit 1
  fi
}

setup_envs() {
  log "Creating virtual environments"
  python3 -m venv "$VULN_VENV"
  python3 -m venv "$FIXED_VENV"
  "$VULN_VENV/bin/pip" install --upgrade pip
  "$FIXED_VENV/bin/pip" install --upgrade pip
  log "Installing $PACKAGE $VULN_VERSION (vulnerable) and $FIXED_VERSION (fixed)"
  "$VULN_VENV/bin/pip" install "${PACKAGE}==${VULN_VERSION}"
  "$FIXED_VENV/bin/pip" install "${PACKAGE}==${FIXED_VERSION}"
}

run_vulnerable_process() {
  log "Starting short-lived process from vulnerable environment"
  "$VULN_VENV/bin/python" -c "import ${PACKAGE//-/_}; print('loaded')" &
  sleep 2
}

collect_evidence() {
  local out="$BUILD/pypi-controlled.openness"
  log "Collect evidence to $out (requires openness-collector on PATH)"
  mkdir -p "$BUILD"
  openness-collector collect --output "$out"
  printf '%s' "$out"
}

validate_resolver() {
  local evidence="$1"
  log "Running resolver"
  "$ROOT/bin/openness-resolver" resolve \
    --input "$evidence" \
    --output "$BUILD/pypi-controlled-findings.json" \
    --data-dir "$ROOT/data"

  python3 - <<'PY' "$BUILD/pypi-controlled-findings.json" "$VULN_VENV" "$FIXED_VENV"
import json, sys
path, vuln_env, fixed_env = sys.argv[1:4]
doc = json.load(open(path))
findings = [f for f in doc["findings"] if f.get("scope") == "python_environment"]
by_env = {f.get("environment_id"): f for f in findings}
# environment ids come from collector evidence; match by venv path in reasons/evidence if needed
vuln = [f for f in findings if f.get("state") in ("vulnerable", "vulnerable_runtime")]
fixed = [f for f in findings if f.get("state") == "fixed"]
assert vuln, "expected vulnerable PyPI finding"
assert fixed, "expected fixed PyPI finding"
assert vuln[0]["finding_id"] != fixed[0]["finding_id"], "environments must produce separate identities"
for f in vuln + fixed:
    assert f.get("comparator") == "pep440" or (f.get("comparison") or {}).get("comparator") == "pep440"
    assert f.get("scope") == "python_environment"
print(json.dumps({"vulnerable": vuln[0], "fixed": fixed[0], "reconciliation": doc.get("reconciliation", {})}, indent=2))
PY
}

main() {
  require_root
  setup_envs
  run_vulnerable_process
  evidence="$(collect_evidence)"
  validate_resolver "$evidence"
  log "Controlled PyPI integration test completed"
}

main "$@"
