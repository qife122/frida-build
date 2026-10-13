#!/usr/bin/env bash
# Minimal, surgical anti-detection patch for frida (Android arm64, v16).
#
# HARD LESSON from previous attempts: broad "frida-" rewrites smash build-system
# identifiers (npm package names like frida-gum / frida-core / @types/frida-gum,
# produced .so names like frida-agent/frida-helper/frida-gadget, error-quark
# symbols, and the kernel header linux/frida-syscall.h). Those MUST stay.
#
# Only TWO things are actually scanned by the target's hardening and are safe
# to change without touching the build graph:
#   (A) the abstract unix socket path, which in source is the quoted literal
#       "/frida-..."  (note the LEADING SLASH — package/module names never have
#       it). Rewriting only "/frida-  ->  "/axsvc-  changes @/frida-<uuid> in
#       /proc/<pid>/net/unix while leaving every package/.so/symbol name alone.
#   (B) frida thread names seen in /proc/<pid>/task/*/comm: the gum JS loop
#       ("gum-js-loop", no "frida-" in it) and the GLib pool name "pool-frida".
#
# Everything else (D-Bus names re.frida.*, frida:rpc wire magic, frida-gum/core
# package names, .so names, quarks, syscall header) is intentionally untouched,
# which also keeps the STOCK python client fully compatible.
set -uo pipefail
cd frida || { echo "ERROR: ./frida not found"; exit 1; }
say(){ echo "=== $* ==="; }

# (A) abstract unix socket literal:  "/frida-  ->  "/axsvc-
#     Anchored on  "/frida-  (double-quote + slash) so it can ONLY match a
#     string literal that starts an absolute-looking socket path. Package names
#     ("frida-gum"), includes (<linux/frida-syscall.h>) and .so names
#     ("frida-agent-64.so") never contain the sequence  "/frida- .
say "(A) socket literal  \"/frida-  ->  \"/axsvc-"
hitA=0
while IFS= read -r f; do
  sed -i 's#"/frida-#"/axsvc-#g' "$f"; echo "  $f"; hitA=$((hitA+1))
done < <(grep -rlF '"/frida-' subprojects/frida-core 2>/dev/null || true)
echo "  files touched: $hitA"

# (A2) socket/pipe base literal WITHOUT leading slash, but ONLY inside the two
#      socket/pipe source files, and ONLY when the literal is "frida-%..." (a
#      printf-style socket template) or "frida-" immediately closed by a quote.
#      This cannot hit package names (frida-gum etc.) because those live in
#      other files and are never written as "frida-%" or a bare "frida-".
say "(A2) socket/pipe template in socket.vala / pipe.vala only"
for f in subprojects/frida-core/lib/base/socket.vala \
         subprojects/frida-core/lib/pipe/pipe.vala; do
  [ -f "$f" ] || continue
  sed -i '/#include/b; /syscall/b; s/"frida-%/"axsvc-%/g; s/"frida-"/"axsvc-"/g' "$f"
  echo "  scanned $f"
done

# (B) thread names (comm scan). Neither contains the substring 'frida-' as a
#     package/module token, so they are safe standalone literals.
say "(B) thread names"
# gum JS run loop -> keep <=15 chars
while IFS= read -r f; do
  sed -i 's/gum-js-loop/gum-ui-loop/g' "$f"; echo "  gum-js-loop: $f"
done < <(grep -rlF 'gum-js-loop' subprojects/frida-gum 2>/dev/null || true)
# GLib thread-pool name (quoted literal)
while IFS= read -r f; do
  sed -i 's/"pool-frida"/"pool-worker"/g' "$f"; echo "  pool-frida: $f"
done < <(grep -rlF '"pool-frida"' subprojects 2>/dev/null || true)

# ---- verification ----
say "VERIFY must-remain (build + wire protocol + stock-client compat)"
for s in 'frida:rpc' 're.frida' 'frida-gum' 'frida-core' 'frida-agent' 'linux/frida-syscall.h'; do
  c=$(grep -rlF "$s" subprojects 2>/dev/null | wc -l)
  echo "  '$s' in $c files (MUST be > 0)"
done

say "VERIFY socket/thread tells rewritten"
echo "  '\"/frida-' remaining : $(grep -rlF '"/frida-' subprojects/frida-core 2>/dev/null | wc -l)  (want 0)"
echo "  '\"/axsvc-' present   : $(grep -rlF '"/axsvc-' subprojects/frida-core 2>/dev/null | wc -l)  (want >0)"
echo "  'gum-js-loop' remain : $(grep -rlF 'gum-js-loop' subprojects 2>/dev/null | wc -l)  (want 0)"

say "patch.sh done"
