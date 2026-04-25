#!/usr/bin/env python3
"""Scan decompiled Ghidra .c files for field accesses off `this`, aggregate
offset-level reads/writes, and print a best-guess struct skeleton.

Input: a directory of .c files produced by DecompileToFiles.java where each
file represents one method of the same class. The first parameter of every
method is implicitly `this` (SystemV ABI: rdi), and Ghidra lowers accesses
like `*(long*)(this + 0x7c0)` which we can grep for.

Output per class (stdout):
  // inferred from N methods
  struct <ClassName> {
      /*+0x10*/ (long / 1 access) ...;
      /*+0x7c0*/ (long / 12 accesses) ...;
      /*+0x7c8*/ (int / 3 accesses) ...;
      ...
  };

Usage:
  infer_struct_fields.py <decompiled-dir> <ClassName>
"""
from __future__ import annotations
import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path


ACCESS_RE = re.compile(
    r"\*?\(\s*(?P<cast>[A-Za-z_][A-Za-z0-9_ \*]*?)\s*\*\s*\)\s*\(\s*"
    r"(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*0x(?P<off>[0-9a-fA-F]+)\s*\)"
)

# Fallback: `in_RDI + 0x7c0` style. Ghidra often emits `in_RDI` as the
# prologue placeholder for `this` before type propagation settles.
_BASE_CANDIDATES = {"this", "in_RDI", "param_1"}


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("dir", type=Path)
    ap.add_argument("class_name")
    ap.add_argument("--top", type=int, default=64,
                    help="max fields to show (default 64)")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    files = sorted(args.dir.glob("*.c"))
    if not files:
        print(f"no .c files in {args.dir}", file=sys.stderr)
        return 1

    # offset -> {cast: count}
    offsets: dict[int, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    n_methods = 0
    for f in files:
        n_methods += 1
        text = f.read_text(errors="replace")
        for m in ACCESS_RE.finditer(text):
            base = m.group("base").strip()
            if base not in _BASE_CANDIDATES:
                continue
            cast = m.group("cast").strip()
            offset = int(m.group("off"), 16)
            offsets[offset][cast] += 1

    if not offsets:
        print(f"no this-relative accesses found in {len(files)} files",
              file=sys.stderr)
        return 1

    max_off = max(offsets.keys())
    print(f"// inferred from {n_methods} methods (max offset seen: 0x{max_off:x})")
    print(f"struct {args.class_name} {{")
    for off in sorted(offsets)[:args.top]:
        by_cast = offsets[off]
        total = sum(by_cast.values())
        dominant = sorted(by_cast.items(), key=lambda x: -x[1])[0]
        cast_summary = ", ".join(f"{c}×{n}" for c, n in
                                 sorted(by_cast.items(), key=lambda x: -x[1]))
        print(f"    /*+0x{off:04x}*/ {dominant[0]} f_{off:x};"
              f"  // {total} access{'es' if total > 1 else ''}, {cast_summary}")
    if len(offsets) > args.top:
        print(f"    // ... {len(offsets) - args.top} more offsets omitted")
    print("};")
    return 0


if __name__ == "__main__":
    sys.exit(main())
