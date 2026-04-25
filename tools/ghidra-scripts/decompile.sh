#!/usr/bin/env bash
# Wrapper for running the DecompileToFiles Ghidra script.
#
# Layout assumed:
#   <workspace>/factorio-re-toolkit/tools/ghidra-scripts/decompile.sh   (this)
#   <workspace>/factorio-re-toolkit/tools/ghidra/support/analyzeHeadless
#   <workspace>/re/symbols/defined.txt
#   <workspace>/re/ghidra-project/
#   <workspace>/re/ghidra-logs/decompile.log
#
# Usage:
#   ./tools/ghidra-scripts/decompile.sh <output-dir> <regex>
# Examples:
#   ./tools/ghidra-scripts/decompile.sh ../re/decompiled/Map        '^Map::'
#   ./tools/ghidra-scripts/decompile.sh ../re/decompiled/Entity     '^Entity::'
#   ./tools/ghidra-scripts/decompile.sh ../re/decompiled/UpdateLoop 'updateEntities|::update\(\)'
# (output dirs are typically under <workspace>/re/decompiled/, i.e. ../re/decompiled/<Class>)

set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
toolkit_root=$(cd "$script_dir/../.." && pwd)
workspace=$(cd "$toolkit_root/.." && pwd)
out=${1:?"output dir required"}
re=${2:?"regex required"}

# Make output path absolute so Ghidra (which has its own cwd) writes correctly.
mkdir -p "$out"
abs_out=$(cd "$out" && pwd)

mkdir -p "$workspace/re/ghidra-logs"
symbols_file="$workspace/re/symbols/defined.txt"
if [ ! -f "$symbols_file" ]; then
  echo "missing $symbols_file" >&2
  echo "run: nm --demangle --defined-only --format=bsd \"$workspace/factorio/bin/x64/factorio\" > \"$symbols_file\"" >&2
  exit 1
fi

cd "$workspace"
"$toolkit_root/tools/ghidra/support/analyzeHeadless" \
  re/ghidra-project factorio_standalone \
  -process factorio \
  -scriptPath "$script_dir" \
  -postScript DecompileToFiles.java "$symbols_file" "$abs_out" "$re" \
  -noanalysis \
  -readOnly 2>&1 | tee "$workspace/re/ghidra-logs/decompile.log"
