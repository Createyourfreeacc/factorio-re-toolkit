#!/usr/bin/env bash
# One-time pass: read nm-derived demangled names, rename matching functions
# in the Ghidra project, save the project. Subsequent decompiles produce
# call sites with real function names instead of FUN_<addr>.
#
# Layout assumed:
#   <workspace>/factorio-re-toolkit/tools/ghidra-scripts/rename_functions.sh
#   <workspace>/factorio-re-toolkit/tools/ghidra/support/analyzeHeadless
#   <workspace>/re/symbols/all.txt   (nm --demangle <factorio>)
#   <workspace>/re/ghidra-project/factorio_standalone/
#
# Usage:
#   ./tools/ghidra-scripts/rename_functions.sh
#
# Mutates the Ghidra project. Idempotent (re-running does nothing on the
# second pass).

set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
toolkit_root=$(cd "$script_dir/../.." && pwd)
workspace=$(cd "$toolkit_root/.." && pwd)

symbols_file="$workspace/re/symbols/all.txt"
if [ ! -f "$symbols_file" ]; then
  echo "missing $symbols_file" >&2
  echo "run: nm --demangle \"$workspace/factorio/bin/x64/factorio\" > \"$symbols_file\"" >&2
  exit 1
fi

mkdir -p "$workspace/re/ghidra-logs"
log="$workspace/re/ghidra-logs/rename.log"

cd "$workspace"
"$toolkit_root/tools/ghidra/support/analyzeHeadless" \
  re/ghidra-project factorio_standalone \
  -process factorio \
  -scriptPath "$script_dir" \
  -postScript RenameFunctions.java "$symbols_file" \
  -noanalysis 2>&1 | tee "$log"

echo
echo "rename log: $log"
echo "Re-run a decompile after this and the .c files will use real names."
