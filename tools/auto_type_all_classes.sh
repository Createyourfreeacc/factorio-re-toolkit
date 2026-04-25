#!/usr/bin/env bash
# Run auto_type_fields.py on every <Class>.inferred.h in re/dwarf/structs/.
#
# Layout:
#   <workspace>/factorio-re-toolkit/tools/auto_type_all_classes.sh  (this)
#   <workspace>/factorio-re-toolkit/tools/auto_type_fields.py
#   <workspace>/re/dwarf/structs/<Class>.inferred.h               (input)
#   <workspace>/re/dwarf/structs/<Class>.auto.h                   (output)
#
# Usage:
#   ./tools/auto_type_all_classes.sh

set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
toolkit_root=$(cd "$script_dir/.." && pwd)
workspace=$(cd "$toolkit_root/.." && pwd)

cd "$workspace"
"$toolkit_root/tools/auto_type_fields.py" "$@"

# Aggregate confidence summary
echo
echo "=== aggregate confidence across all classes ==="
total_high=0
total_medium=0
total_reject=0
for f in re/dwarf/structs/*.auto.h; do
  cls=$(basename "$f" .auto.h)
  high=$(grep -c '/\*.*conf:high\*/' "$f" || true)
  medium=$(grep -c '/\*.*conf:medium\*/' "$f" || true)
  reject=$(grep -c '/\*.*conf:reject\*/' "$f" || true)
  total=$((high + medium + reject))
  printf "  %-20s  high=%-3d  medium=%-3d  reject=%-3d  total=%-3d\n" \
    "$cls" "$high" "$medium" "$reject" "$total"
  total_high=$((total_high + high))
  total_medium=$((total_medium + medium))
  total_reject=$((total_reject + reject))
done
echo "  ----"
total_all=$((total_high + total_medium + total_reject))
printf "  TOTALS              high=%-3d  medium=%-3d  reject=%-3d  total=%-3d\n" \
  "$total_high" "$total_medium" "$total_reject" "$total_all"
