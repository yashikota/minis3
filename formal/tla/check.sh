#!/usr/bin/env bash
# Model-check every TLA+ specification in this directory with TLC.
# Each <Spec>*.cfg is checked against <Spec>.tla (the config name starts
# with the spec name). Uses the single-executable TLC from
# https://github.com/yashikota/tlc-static (no Java needed), installed and
# version-pinned through aqua (see aqua.yaml); set TLC_BIN to use another
# binary.
set -euo pipefail

cd "$(dirname "$0")"

TLC="${TLC_BIN:-tlc}"
if ! command -v "$TLC" >/dev/null; then
  echo "TLC binary '${TLC}' not found; run 'aqua install' or set TLC_BIN" >&2
  exit 1
fi
"$TLC" -h 2>&1 | grep -m1 "Version" || true

status=0
for cfg in *.cfg; do
  spec=""
  for tla in *.tla; do
    name="${tla%.tla}"
    case "$cfg" in
      "$name"*.cfg) spec="$tla" ;;
    esac
  done
  echo "==> TLC: ${spec} with ${cfg}"
  if ! "$TLC" -workers auto -deadlock -config "$cfg" "$spec" |
    tee ".tlc-${cfg%.cfg}.log" | grep -E "Model checking completed|Error|violated|states generated"; then
    status=1
  fi
  grep -q "Model checking completed. No error has been found." ".tlc-${cfg%.cfg}.log" || status=1
done
rm -rf states
exit "$status"
