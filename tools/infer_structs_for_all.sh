#!/usr/bin/env bash
# Run infer_struct_fields.py on every per-class directory under
# <workspace>/re/decompiled/ and deposit the results in
# <workspace>/re/dwarf/structs/.
#
# Layout assumed:
#   <workspace>/factorio-re-toolkit/tools/infer_structs_for_all.sh  (this)
#   <workspace>/factorio-re-toolkit/tools/infer_struct_fields.py
#   <workspace>/re/decompiled/<Class>/*.c
#   <workspace>/re/dwarf/structs/                                   (output)
#
# Usage:
#   ./tools/infer_structs_for_all.sh

set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
toolkit_root=$(cd "$script_dir/.." && pwd)
workspace=$(cd "$toolkit_root/.." && pwd)
cd "$workspace"

out="re/dwarf/structs"
mkdir -p "$out"

n=0
empty=0
for d in re/decompiled/*/; do
  cls=$(basename "$d")
  case "$cls" in _batch|_*) continue ;; esac
  if [ -z "$(ls "$d"/*.c 2>/dev/null)" ]; then
    continue
  fi
  result=$(python3 "$toolkit_root/tools/infer_struct_fields.py" --top 400 "$d" "$cls" 2>&1 || true)
  if [ -z "$result" ] || echo "$result" | grep -q 'no this-relative accesses found'; then
    empty=$((empty+1))
    continue
  fi
  echo "$result" > "$out/${cls}.inferred.h"
  fields=$(echo "$result" | grep -c '/\*+0x' || true)
  methods=$(echo "$result" | awk -F'from ' '/inferred from/ {print $2; exit}' | awk '{print $1}')
  printf "  %-20s  %3s fields across %s methods\n" "$cls" "$fields" "${methods:-?}"
  n=$((n+1))
done

echo
echo "wrote $n inferred headers to $out/ (skipped $empty empty)"
