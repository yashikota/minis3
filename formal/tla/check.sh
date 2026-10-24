#!/usr/bin/env bash
# Model-check every TLA+ specification in this directory with TLC.
# Each <Spec>*.cfg is checked against <Spec>.tla (the config name starts
# with the spec name). Uses the single-executable TLC from
# https://github.com/yashikota/tlc-static (no Java needed), downloading a
# pinned, checksum-verified release; set TLC_BIN to use another binary.
set -euo pipefail

cd "$(dirname "$0")"

TLC_VERSION="v2026.10.23.134125"

tlc_asset() {
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64 | Linux-amd64) echo "tlc-linux-amd64.tar.gz 7ce9bd9144a9f39c6b7bdec1bfc38a41c8cf883bda57034ecd02b89a410a2b3a" ;;
    Linux-aarch64 | Linux-arm64) echo "tlc-linux-arm64.tar.gz a39f7ace30a36980459d594590aefcfef4bb08931595e100cbb2f47e9a01b26e" ;;
    Darwin-arm64) echo "tlc-macos-arm64.tar.gz 2b0aee1d643137d45598293c2c67ea93cbd5679ac6d9d1486e3329b3131ab10a" ;;
    *)
      echo "unsupported platform $(uname -s)-$(uname -m); set TLC_BIN" >&2
      return 1
      ;;
  esac
}

TLC="${TLC_BIN:-}"
if [ -z "$TLC" ]; then
  dir=".tlc-${TLC_VERSION}"
  TLC="${dir}/tlc"
  if [ ! -x "$TLC" ]; then
    read -r asset sha256 < <(tlc_asset)
    mkdir -p "$dir"
    curl -fsSL -o "${dir}/${asset}" \
      "https://github.com/yashikota/tlc-static/releases/download/${TLC_VERSION}/${asset}"
    if command -v sha256sum >/dev/null; then
      echo "${sha256}  ${dir}/${asset}" | sha256sum -c - >/dev/null
    else
      echo "${sha256}  ${dir}/${asset}" | shasum -a 256 -c - >/dev/null
    fi
    tar -xzf "${dir}/${asset}" -C "$dir" tlc
    rm -f "${dir}/${asset}"
  fi
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
