#!/usr/bin/env python3
"""Partition a flat directory of Ghidra-decompiled .c files into per-class
subdirectories by leading class name.

Each filename produced by DecompileToFiles.java begins with the demangled
signature (with :: replaced by :: preserved and parameter chars sanitized),
e.g.:
    Entity::update__.c
    LuaEntity::get_health__.c
    Map::createSurface_std::...__<hash>.c

This script extracts the leading top-level class token (before the first
`::`) and moves each file into `<out>/<Class>/<basename>`.

Usage:
    partition_decompiled.py <src-dir> <out-dir> [--move | --copy]

Default is --move (rename). Use --copy to preserve originals.
"""
from __future__ import annotations
import argparse
import re
import shutil
import sys
from collections import Counter
from pathlib import Path


_CLASS_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)::")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser()
    ap.add_argument("src", type=Path)
    ap.add_argument("out", type=Path)
    op = ap.add_mutually_exclusive_group()
    op.add_argument("--move", action="store_true", default=True)
    op.add_argument("--copy", action="store_true")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    if args.copy:
        args.move = False
    if not args.src.is_dir():
        print(f"source is not a directory: {args.src}", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)

    counts: Counter[str] = Counter()
    unclassified = 0
    for f in sorted(args.src.iterdir()):
        if not f.is_file() or not f.name.endswith(".c"):
            continue
        m = _CLASS_RE.match(f.name)
        if not m:
            unclassified += 1
            continue
        cls = m.group(1)
        target_dir = args.out / cls
        target_dir.mkdir(exist_ok=True)
        target = target_dir / f.name
        if args.copy:
            shutil.copy2(f, target)
        else:
            f.rename(target)
        counts[cls] += 1

    total = sum(counts.values())
    print(f"partitioned {total} files into {len(counts)} classes "
          f"({unclassified} unclassified)")
    for cls, n in counts.most_common():
        print(f"  {n:5d}  {cls}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
