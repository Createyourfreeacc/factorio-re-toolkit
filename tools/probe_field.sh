#!/usr/bin/env bash
# probe_field.sh <ClassName> <offset_hex>
#
# Three certainty checks for a single struct field:
#
#   1. INSTRUCTION WIDTH — disassembles every <ClassName>:: function and
#      reports each unique mnemonic + operand size that touches the given
#      offset. Tells you 1/2/4/8 bytes and signed-vs-unsigned with certainty.
#
#   2. DECOMPILED USE SITES — greps re/decompiled/<ClassName>/ for every
#      access expression involving the offset, so you can see the type as
#      Ghidra inferred it from the surrounding code.
#
#   3. RUNTIME PROBE (optional, --gdb) — generates a gdb command file you
#      can run against an attached factorio process to read the field's
#      live value at four candidate widths (uint8/16/32/64), so you can
#      see which width contains a sensible value.
#
# Together: width and signedness from #1, type kind from #2, semantic role
# from #3. If all three agree, you can commit to a type with confidence.
#
# Layout assumed (same as other toolkit scripts):
#   <workspace>/factorio-re-toolkit/tools/probe_field.sh   (this)
#   <workspace>/factorio/bin/x64/factorio
#   <workspace>/re/symbols/defined.txt
#   <workspace>/re/decompiled/<ClassName>/
#
# Usage:
#   ./tools/probe_field.sh Map 0x18
#   ./tools/probe_field.sh Inserter 0x42
#   ./tools/probe_field.sh CraftingMachine 0x14 --gdb     # also print gdb cmds

set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: $0 <ClassName> <offset_hex>  [--gdb]" >&2
  echo "examples:" >&2
  echo "  $0 Map 0x18" >&2
  echo "  $0 Inserter 0x42 --gdb" >&2
  exit 1
fi

cls="$1"
off_hex="$2"
shift 2
gdb_mode=0
for arg in "$@"; do
  case "$arg" in
    --gdb) gdb_mode=1 ;;
    *) echo "unknown flag: $arg" >&2; exit 1 ;;
  esac
done

# Normalize offset_hex to a numeric form for matching. Accept "0x18", "18",
# or "0x0018" interchangeably.
norm=$(printf "0x%x" "$((off_hex))")

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
toolkit_root=$(cd "$script_dir/.." && pwd)
workspace=$(cd "$toolkit_root/.." && pwd)
binary="$workspace/factorio/bin/x64/factorio"
symbols="$workspace/re/symbols/defined.txt"
decompiled="$workspace/re/decompiled/$cls"

if [ ! -x "$binary" ]; then
  echo "no factorio binary at $binary" >&2; exit 1
fi
if [ ! -f "$symbols" ]; then
  echo "no nm output at $symbols" >&2; exit 1
fi

echo "=========================================================="
echo "probe_field: ${cls}::f_${norm#0x}     offset = $norm"
echo "=========================================================="

# ---------------------------------------------------------------------
# 1. INSTRUCTION WIDTH from objdump
# ---------------------------------------------------------------------
echo
echo "--- (1) instruction widths touching $norm in ${cls}::* methods ---"

# Collect all symbols whose demangled form starts with "<cls>::" and the
# extra constraint that nothing other than `<` or `:` follows the class
# name (avoids matching e.g. `MapBase` when probing `Map`).
addrs=$(awk -v cls="$cls" '
  $2 ~ /^[TtWwiu]$/ && $3 ~ "^" cls "(::|<)" {
    printf "0x%s\n", $1
  }' "$symbols")

if [ -z "$addrs" ]; then
  echo "  (no ${cls}:: functions found in symbol table; check spelling)"
else
  count=$(echo "$addrs" | wc -l)
  echo "  scanning $count ${cls}:: functions..."

  # Disassemble each function in turn. We look for memory operand
  # patterns referencing the offset:
  #   [reg + 0xNN]   — direct
  #   [reg+reg + 0xNN]  — indexed
  pattern="\\+${off_hex/0x/0x}"
  patternA="+ ${off_hex}\\]"
  patternB="+${off_hex}\\]"

  # Iterate addresses; for each, --start/--stop disassemble. Slow per call,
  # but bounded: typical class has 20-200 methods. We disable
  # objdump's pagination by piping straight to grep.
  while read -r a; do
    [ -z "$a" ] && continue
    # Disassemble up to 16 KB from the function start. Most functions are
    # smaller; we don't have the size, so over-shoot and let grep filter.
    objdump -d --start-address="$a" --stop-address="$((a + 0x4000))" \
            --no-show-raw-insn -M intel "$binary" 2>/dev/null \
      | grep -E "[+-]\s*${off_hex}\\]" || true
  done <<< "$addrs" | awk '
    {
      mnemonic = $2
      lc = tolower($0)
      operand_size = "?"
      if (lc ~ /xmmword *ptr/)       operand_size = "xmm  (16B)"
      else if (lc ~ /ymmword *ptr/)  operand_size = "ymm  (32B)"
      else if (lc ~ /qword *ptr/)    operand_size = "qword (8B)"
      else if (lc ~ /dword *ptr/)    operand_size = "dword (4B)"
      else if (lc ~ /word *ptr/)     operand_size = "word  (2B)"
      else if (lc ~ /byte *ptr/)     operand_size = "byte  (1B)"
      # Infer signed-ness for the 1- and 2-byte cases via mnemonic
      sign = ""
      if (mnemonic == "movzx")        sign = " (unsigned)"
      else if (mnemonic == "movsx" || mnemonic == "movsxd") sign = " (signed)"
      key = sprintf("%-10s  %-13s%s", mnemonic, operand_size, sign)
      counts[key]++
      example[key] = $0
    }
    END {
      if (length(counts) == 0) {
        print "  (no instructions found that touch this offset)"
      } else {
        # Sort by count desc by post-processing in shell; here just emit.
        for (k in counts) {
          printf "  %5d ×  %s    e.g.  %s\n", counts[k], k, example[k]
        }
      }
    }
  ' | sort -rn
fi

# ---------------------------------------------------------------------
# 2. DECOMPILED USE SITES
# ---------------------------------------------------------------------
echo
echo "--- (2) decompiled access patterns in re/decompiled/${cls}/ ---"
if [ ! -d "$decompiled" ]; then
  echo "  (no decompiled output for $cls; run decompile.sh + partition first)"
else
  # Match patterns Ghidra emits for `this + 0xN` accesses. The base may be
  # in_RDI (raw param) or this (after type propagation).
  matched=$(grep -rhE "\\(in_RDI \\+ ${off_hex}\\)|\\(this \\+ ${off_hex}\\)|\\(param_1 \\+ ${off_hex}\\)|->.*${off_hex}" \
                "$decompiled"/*.c 2>/dev/null | sort -u | head -25)
  if [ -z "$matched" ]; then
    echo "  (no access patterns found at $norm in decompiled output)"
  else
    echo "$matched" | sed 's/^/  /'
    echo
    echo "  (showing first 25 unique lines; grep manually for full list)"
  fi
fi

# ---------------------------------------------------------------------
# 3. RUNTIME PROBE — gdb command preamble
# ---------------------------------------------------------------------
if [ "$gdb_mode" = 1 ]; then
  echo
  echo "--- (3) runtime probe via gdb ---"
  cat <<EOF

To verify the field's live value, attach gdb to a running factorio:

  # 1. start the game, load a save, let it tick a few frames
  ./mods/native/scripts/run_factorio.sh

  # 2. in another terminal, attach
  gdb -p \$(pgrep -f 'bin/x64/factorio$' | head -1)

  # 3. paste these gdb commands. They break in a known ${cls} method
  #    where RDI = ${cls}*, then read the field at four widths:

  set pagination off
  break ${cls}::update if \$rdi != 0
  continue

  # When the breakpoint hits:
  set \$obj = (char*)\$rdi
  printf "addr      = %p\n", \$obj
  printf "qword (u8)= 0x%016lx  =  %lu\n", *(unsigned long*)(\$obj+${norm}), *(unsigned long*)(\$obj+${norm})
  printf "qword (s8)= %ld\n", *(long*)(\$obj+${norm})
  printf "dword (u4)= 0x%08x  =  %u\n",  *(unsigned int*)(\$obj+${norm}), *(unsigned int*)(\$obj+${norm})
  printf "dword (s4)= %d\n", *(int*)(\$obj+${norm})
  printf "word  (u2)= 0x%04x  =  %u\n", *(unsigned short*)(\$obj+${norm}), *(unsigned short*)(\$obj+${norm})
  printf "byte  (u1)= 0x%02x  =  %u\n", *(unsigned char*)(\$obj+${norm}), *(unsigned char*)(\$obj+${norm})
  printf "ptr       = %p\n", *(void**)(\$obj+${norm})
  printf "float     = %f\n", *(float*)(\$obj+${norm})
  printf "double    = %lf\n", *(double*)(\$obj+${norm})

  # 4. continue, hit it again on next tick, observe whether values change.
  #    A monotonic counter, a stable config, a pointer to mapped memory,
  #    or a wildly-changing hot state are all distinguishable here.
  continue

To read this offset across many ${cls} instances at once (when you have
a Map* / Surface* etc. iterator), see:
  ${toolkit_root}/tools/probe_field.sh --batch  (not yet implemented)
EOF
fi

echo
echo "=========================================================="
echo "Interpretation guide:"
echo "  - All checks should AGREE on size + signedness."
echo "  - 'movzx' → unsigned, 'movsx' → signed (otherwise either)."
echo "  - 'movss/movsd' or xmm-register destination → float/double."
echo "  - Mixed widths at same offset → packed bitfield or union; do NOT"
echo "    name as a single typed field."
echo "  - If runtime probe shows the qword view as a pointer-shaped"
echo "    address (0x7f...) and other views as junk, it's a pointer."
echo "=========================================================="
