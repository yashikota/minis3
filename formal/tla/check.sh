#!/usr/bin/env bash
# Model-check every TLA+ specification in this directory with TLC.
# Each <Spec>*.cfg is checked against <Spec>.tla (the config name starts
# with the spec name). Requires Java 11+; downloads a pinned tla2tools.jar.
set -euo pipefail

cd "$(dirname "$0")"

TLA_VERSION="v1.7.4"
TLA_SHA256="936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
JAR="${TLA2TOOLS_JAR:-.tla2tools-${TLA_VERSION}.jar}"

if [ ! -f "$JAR" ]; then
  curl -fsSL -o "$JAR" \
    "https://github.com/tlaplus/tlaplus/releases/download/${TLA_VERSION}/tla2tools.jar"
fi
echo "${TLA_SHA256}  ${JAR}" | sha256sum -c - >/dev/null

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
  if ! java -XX:+UseParallelGC -cp "$JAR" tlc2.TLC -workers auto -deadlock \
    -config "$cfg" "$spec" | tee ".tlc-${cfg%.cfg}.log" | grep -E "Model checking completed|Error|violated|states generated"; then
    status=1
  fi
  grep -q "Model checking completed. No error has been found." ".tlc-${cfg%.cfg}.log" || status=1
done
rm -rf states
exit "$status"
