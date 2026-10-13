#!/usr/bin/env bash
# Patch frida source to evade the specific anti-debug checks observed on the
# target (SecNeo hardening on com.qihuo.yinhe):
#   - /proc/<pid>/net/unix scan for the abstract socket "@/frida-<uuid>"
#   - /proc/<pid>/task/*/comm scan for frida thread names
#   - /proc/<pid>/maps / cmdline scan for frida identifiers
#
# DESIGN CHANGE vs the previous (failed) attempt:
#   * DO NOT touch the D-Bus well-known names (re.frida.HostSession16 etc).
#     Those are logical interface names, NOT part of the socket path, and
#     changing them only breaks compatibility with the stock python client.
#   * DO change the abstract unix socket prefix "/frida-" -> "/axsvc-", which
#     is what actually shows up in /proc/<pid>/net/unix.
#   * Keep 'frida:rpc' (wire magic) and frida_agent_main (exported symbol) intact
#     so the stock client still talks to this server.
#
# Run from repo root; expects ./frida (cloned with submodules).
set -uo pipefail
cd frida || { echo "ERROR: ./frida not found"; exit 1; }

say(){ echo "=== $* ==="; }

# Equal-semantics textual replacements. Lengths need not match (source build).
# 1) Abstract socket / pipe prefix — the real /proc/net/unix tell.
#    CRITICAL: exclude #include lines and any line mentioning 'syscall', so we
#    never touch  #include <linux/frida-syscall.h>  (frida's own kernel header).
#    Only genuine string literals like "/frida-%u" get rewritten.
say "1) abstract unix socket prefix  /frida- -> /axsvc-  (include/syscall-safe)"
grep -rlF '/frida-' subprojects/frida-core 2>/dev/null | while read -r f; do
  sed -i '/#include/b; /syscall/b; s#/frida-#/axsvc-#g' "$f"; echo "  $f"
done

# bare "frida-" string literal used as a pipe/endpoint base in socket.vala / pipe.vala
say "2) pipe/socket base string literals in base/pipe vala"
for f in subprojects/frida-core/lib/base/socket.vala \
         subprojects/frida-core/lib/pipe/pipe.vala; do
  [ -f "$f" ] || continue
  # only quoted literals; include lines never use quotes like this
  sed -i '/#include/b; /syscall/b; s/"frida-/"axsvc-/g' "$f"
  echo "  patched $f"
done

# 3) thread names (comm scan, <=15 chars each)
say "3) thread / loop names (comm scan)"
declare -A TN=(
  ["gum-js-loop"]="gum-ui-loop"
  ["frida-main-loop"]="axsvc-main-lp"
  ["frida-ctrl"]="axsvc-ctrl"
  ["frida-context"]="axsvc-context"
)
for old in "${!TN[@]}"; do
  new="${TN[$old]}"
  grep -rlF "$old" subprojects 2>/dev/null | while read -r f; do
    sed -i "/#include/b; /syscall/b; s/${old}/${new}/g" "$f"; echo "  $old -> $new : $f"
  done
done
# pool-frida / "frida-gum" GLib thread pool & source names
grep -rlF '"pool-frida"' subprojects 2>/dev/null | while read -r f; do
  sed -i '/#include/b; /syscall/b; s/"pool-frida"/"pool-worker"/g' "$f"; echo "  pool-frida : $f"; done
grep -rlF 'frida-eternal-agent' subprojects 2>/dev/null | while read -r f; do
  sed -i '/#include/b; /syscall/b; s/frida-eternal-agent/axsvc-eternal-agt/g' "$f"; echo "  eternal-agent : $f"; done

# 4) injected agent library name (visible in target /proc/<pid>/maps)
# NOTE: left DISABLED by default. Renaming the agent .so touches both the
# source loader and the meson build/resource packaging; if they fall out of
# sync the server builds but fails to inject. Enable only if a maps-based
# 'frida-agent' detection survives the socket/thread patches above.
# To enable: set PATCH_AGENT=1 in the environment before running.
if [ "${PATCH_AGENT:-0}" = "1" ]; then
  say "4) agent .so names (maps scan) [ENABLED]"
  grep -rlE 'frida-agent' subprojects/frida-core 2>/dev/null | while read -r f; do
    sed -i 's/frida-agent/axsvc-agent/g' "$f"; echo "  $f"
  done
else
  say "4) agent .so rename SKIPPED (set PATCH_AGENT=1 to enable)"
fi

# ---- safety: confirm we did NOT break the wire protocol ----
say "VERIFY: protocol-critical strings must remain"
for s in 'frida:rpc' 're.frida' 'frida_agent_main'; do
  c=$(grep -rlF "$s" subprojects 2>/dev/null | wc -l)
  echo "  '$s' present in $c files (MUST be > 0)"
done

say "VERIFY: detectable tells should be gone"
for s in '/frida-' 'gum-js-loop' 'frida-main-loop' 'frida-agent-arm64.so'; do
  c=$(grep -rlF "$s" subprojects 2>/dev/null | wc -l)
  echo "  '$s' still in $c files (lower=better)"
done

say "patch.sh done"
