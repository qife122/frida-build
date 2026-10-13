#!/usr/bin/env bash
# Patch frida source to strip anti-debug detectable signatures.
# Run from the repo root; expects ./frida (already cloned with submodules).
# Uses grep to locate strings dynamically — no hardcoded line numbers.
#
# What it changes (client AND server compiled from the same tree, so endpoint
# names stay consistent on both sides — that is the whole point of a source
# build vs a binary patch):
#   1. thread names  -> defeat /proc/<pid>/task/*/comm scanning
#   2. re.frida.*    -> D-Bus well-known name + abstract unix socket name,
#                       defeats /proc/<pid>/net/unix scanning
#   3. pipe/pool names
# It deliberately does NOT touch 'frida:rpc' (the wire-protocol magic that the
# client and server must agree on) or the frida_agent_main exported symbol.
set -uo pipefail
cd frida || { echo "ERROR: ./frida not found"; exit 1; }

say(){ echo "=== $* ==="; }
repl(){ # repl <old> <new> <subtree>
  local old="$1" new="$2" sub="$3" n=0
  while IFS= read -r f; do
    sed -i "s/${old}/${new}/g" "$f" && { echo "  [$sub] $f"; n=$((n+1)); }
  done < <(grep -rlF "$(printf '%s' "$old" | sed 's/\\\\//g')" "$sub" 2>/dev/null || true)
  echo "  -> $old : $n files"
}

say "1) thread names (comm scan: /proc/<pid>/task/*/comm, max 15 chars)"
# gum-js-loop -> keep <=15 chars, avoid 'frida'/'gum-js' literal
grep -rl 'gum-js-loop' subprojects/frida-gum 2>/dev/null | while read -r f; do
  sed -i 's/gum-js-loop/gmain-ui-loop/g' "$f"; echo "  $f"; done || true
grep -rl '"pool-frida"' subprojects 2>/dev/null | while read -r f; do
  sed -i 's/"pool-frida"/"pool-worker"/g' "$f"; echo "  $f"; done || true
grep -rl '"frida-gum"' subprojects/frida-gum 2>/dev/null | while read -r f; do
  sed -i 's/"frida-gum"/"libgumx-rt"/g' "$f"; echo "  $f"; done || true

say "2) D-Bus / abstract unix socket name (net/unix scan)"
# re.frida.* appears as the DBus well-known name and the abstract socket.
# Replacing it everywhere in frida-core keeps client<->server consistent.
grep -rl 're\.frida' subprojects/frida-core 2>/dev/null | while read -r f; do
  sed -i 's/re\.frida/re\.axcorp/g' "$f"; echo "  $f"; done || true

say "3) pipe / injector socket prefixes"
grep -rl 'frida-pipe' subprojects/frida-core 2>/dev/null | while read -r f; do
  sed -i 's/frida-pipe/axcorp-pipe/g' "$f"; echo "  $f"; done || true

say "VERIFY: frida:rpc must remain (wire protocol)"
if grep -rq 'frida:rpc' subprojects/frida-core 2>/dev/null; then
  echo "  OK frida:rpc intact"
else
  echo "  NOTE frida:rpc not found under frida-core (may live elsewhere)"
fi

say "VERIFY: residual tells"
for s in 'gum-js-loop' '"pool-frida"' 're.frida'; do
  c=$(grep -rl "$s" subprojects 2>/dev/null | wc -l)
  echo "  '$s' still in $c files (lower is better)"
done

say "patch.sh done"
