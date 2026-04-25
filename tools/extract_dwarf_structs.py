#!/usr/bin/env python3
"""Extract DWARF struct/class layouts from an ELF binary.

For each class name listed on the command line (or matched by a regex),
prints a C-style declaration with member types, names, and byte offsets.
Resolves DW_AT_type chains so types come out as readable names instead of
DIE offsets.

Usage:
  extract_dwarf_structs.py <binary> [--class Name]... [--regex 'pattern']
                                    [--output-dir <dir>] [--all-named]

If --output-dir is given, writes one file per class into that directory
named <Class>.h. Otherwise prints to stdout.
"""
from __future__ import annotations
import argparse
import os
import re
import sys
from collections.abc import Iterable
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.dwarf.die import DIE
from elftools.dwarf.compileunit import CompileUnit


def attr(die: DIE, name: str):
    a = die.attributes.get(name)
    return a.value if a is not None else None


def attr_str(die: DIE, name: str) -> str | None:
    v = attr(die, name)
    if v is None:
        return None
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace")
    return str(v)


def resolve_type(die: DIE, depth: int = 0) -> str:
    """Return a readable C type name for a type-DIE."""
    if depth > 20:
        return "?recursion?"
    tag = die.tag
    name = attr_str(die, "DW_AT_name")
    if tag == "DW_TAG_base_type":
        return name or "?base?"
    if tag in ("DW_TAG_typedef", "DW_TAG_const_type", "DW_TAG_volatile_type",
               "DW_TAG_atomic_type", "DW_TAG_restrict_type"):
        ref = attr(die, "DW_AT_type")
        prefix = {
            "DW_TAG_const_type": "const ",
            "DW_TAG_volatile_type": "volatile ",
            "DW_TAG_atomic_type": "_Atomic ",
            "DW_TAG_restrict_type": "restrict ",
        }.get(tag, "")
        if name:
            return prefix + name
        if ref is not None:
            return prefix + resolve_type(die.cu.get_DIE_from_refaddr(ref), depth + 1)
        return prefix + "?"
    if tag == "DW_TAG_pointer_type":
        ref = attr(die, "DW_AT_type")
        if ref is None:
            return "void*"
        return resolve_type(die.cu.get_DIE_from_refaddr(ref), depth + 1) + "*"
    if tag == "DW_TAG_reference_type":
        ref = attr(die, "DW_AT_type")
        if ref is None:
            return "void&"
        return resolve_type(die.cu.get_DIE_from_refaddr(ref), depth + 1) + "&"
    if tag == "DW_TAG_rvalue_reference_type":
        ref = attr(die, "DW_AT_type")
        if ref is None:
            return "void&&"
        return resolve_type(die.cu.get_DIE_from_refaddr(ref), depth + 1) + "&&"
    if tag == "DW_TAG_array_type":
        ref = attr(die, "DW_AT_type")
        elem = resolve_type(die.cu.get_DIE_from_refaddr(ref), depth + 1) if ref is not None else "?"
        # try to read DW_TAG_subrange_type child for the count
        size = ""
        for c in die.iter_children():
            if c.tag == "DW_TAG_subrange_type":
                ub = attr(c, "DW_AT_upper_bound")
                cnt = attr(c, "DW_AT_count")
                if cnt is not None:
                    size = f"[{cnt}]"
                elif ub is not None:
                    size = f"[{int(ub) + 1}]"
                else:
                    size = "[]"
                break
        return elem + size
    if tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type",
               "DW_TAG_enumeration_type"):
        return name or "?anon?"
    if tag == "DW_TAG_subroutine_type":
        ret_ref = attr(die, "DW_AT_type")
        ret = resolve_type(die.cu.get_DIE_from_refaddr(ret_ref), depth + 1) if ret_ref is not None else "void"
        params = []
        for c in die.iter_children():
            if c.tag == "DW_TAG_formal_parameter":
                pref = attr(c, "DW_AT_type")
                params.append(
                    resolve_type(die.cu.get_DIE_from_refaddr(pref), depth + 1)
                    if pref is not None else "?")
        return f"{ret}(*)({', '.join(params)})"
    if tag == "DW_TAG_unspecified_type":
        return name or "?unspec?"
    return name or f"?<{tag}>?"


def fmt_member(die: DIE) -> str | None:
    if die.tag != "DW_TAG_member":
        return None
    name = attr_str(die, "DW_AT_name") or "?"
    tref = attr(die, "DW_AT_type")
    type_str = "?"
    if tref is not None:
        try:
            type_str = resolve_type(die.cu.get_DIE_from_refaddr(tref))
        except Exception as e:
            type_str = f"?{type(e).__name__}?"
    offset = attr(die, "DW_AT_data_member_location")
    bit_offset = attr(die, "DW_AT_data_bit_offset")
    bit_size = attr(die, "DW_AT_bit_size")
    is_static = "DW_AT_external" in die.attributes and "DW_AT_data_member_location" not in die.attributes
    prefix = "static " if is_static else ""
    pos = ""
    if offset is not None:
        pos = f"  // +0x{int(offset):x} (={int(offset)})"
    if bit_offset is not None and bit_size is not None:
        pos = f"  // bit_offset={bit_offset} bit_size={bit_size}"
    return f"  {prefix}{type_str} {name};{pos}"


def fmt_method(die: DIE) -> str | None:
    if die.tag != "DW_TAG_subprogram":
        return None
    name = attr_str(die, "DW_AT_name")
    if not name:
        return None
    ret_ref = attr(die, "DW_AT_type")
    ret = resolve_type(die.cu.get_DIE_from_refaddr(ret_ref)) if ret_ref is not None else "void"
    params = []
    for c in die.iter_children():
        if c.tag == "DW_TAG_formal_parameter":
            pref = attr(c, "DW_AT_type")
            pname = attr_str(c, "DW_AT_name") or ""
            ptype = resolve_type(c.cu.get_DIE_from_refaddr(pref)) if pref is not None else "?"
            if attr(c, "DW_AT_artificial"):
                continue  # skip implicit `this`
            params.append((ptype + " " + pname).strip())
    is_virtual = "DW_AT_virtuality" in die.attributes
    is_static = "DW_AT_object_pointer" not in die.attributes and not any(
        attr(c, "DW_AT_artificial") for c in die.iter_children()
        if c.tag == "DW_TAG_formal_parameter")
    qualifiers = []
    if is_virtual:
        qualifiers.append("virtual")
    if is_static:
        qualifiers.append("static")
    qstr = (" ".join(qualifiers) + " ") if qualifiers else ""
    return f"  {qstr}{ret} {name}({', '.join(params)});"


def fmt_inheritance(die: DIE) -> str | None:
    if die.tag != "DW_TAG_inheritance":
        return None
    tref = attr(die, "DW_AT_type")
    if tref is None:
        return None
    try:
        base = resolve_type(die.cu.get_DIE_from_refaddr(tref))
    except Exception:
        base = "?"
    offset = attr(die, "DW_AT_data_member_location")
    return f"  // : {base} (offset 0x{int(offset):x})" if offset is not None else f"  // : {base}"


def render_class(die: DIE) -> str:
    name = attr_str(die, "DW_AT_name") or "?anon?"
    size = attr(die, "DW_AT_byte_size")
    out = []
    head = "class" if die.tag == "DW_TAG_class_type" else "struct"
    out.append(f"// from CU: {die.cu.get_top_DIE().attributes.get('DW_AT_name', '?')}")
    out.append(f"{head} {name} {{  // size: {size or '?'} bytes ({(size or 0):#x})")
    bases = [fmt_inheritance(c) for c in die.iter_children()]
    bases = [b for b in bases if b]
    for b in bases:
        out.append(b)
    if bases:
        out.append("")
    members = [fmt_member(c) for c in die.iter_children()]
    members = [m for m in members if m]
    for m in members:
        out.append(m)
    if members:
        out.append("")
    methods = [fmt_method(c) for c in die.iter_children()]
    methods = [m for m in methods if m]
    for m in methods[:120]:  # cap output for huge classes
        out.append(m)
    if len(methods) > 120:
        out.append(f"  // ... ({len(methods) - 120} more methods omitted)")
    out.append("};")
    return "\n".join(out) + "\n"


def find_classes(cu: CompileUnit, names: set[str], regex: re.Pattern | None) -> Iterable[DIE]:
    for die in cu.iter_DIEs():
        if die.tag not in ("DW_TAG_class_type", "DW_TAG_structure_type"):
            continue
        if attr(die, "DW_AT_declaration"):
            continue  # skip forward declarations
        name = attr_str(die, "DW_AT_name")
        if not name:
            continue
        if names and name in names:
            yield die
            continue
        if regex and regex.search(name):
            yield die


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", type=Path)
    ap.add_argument("--class", dest="classes", action="append", default=[])
    ap.add_argument("--regex", default=None)
    ap.add_argument("--output-dir", type=Path, default=None)
    ap.add_argument("--limit-per-class", type=int, default=1,
                    help="how many definitions per class name to keep "
                         "(template instantiations / re-emissions can produce many)")
    args = ap.parse_args()

    names = set(args.classes)
    rx = re.compile(args.regex) if args.regex else None
    if not names and not rx:
        print("provide --class or --regex", file=sys.stderr)
        return 1

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)

    seen_per_name: dict[str, int] = {}
    found_total = 0

    with args.binary.open("rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("no DWARF info", file=sys.stderr)
            return 2
        dwarf = elf.get_dwarf_info()
        cu_count = 0
        for cu in dwarf.iter_CUs():
            cu_count += 1
            for die in find_classes(cu, names, rx):
                cname = attr_str(die, "DW_AT_name") or "?"
                count = seen_per_name.get(cname, 0)
                if count >= args.limit_per_class:
                    continue
                seen_per_name[cname] = count + 1
                rendered = render_class(die)
                found_total += 1
                if args.output_dir:
                    safe = re.sub(r"[^A-Za-z0-9._:+-]", "_", cname)
                    suffix = "" if count == 0 else f".{count}"
                    out = args.output_dir / f"{safe}{suffix}.h"
                    out.write_text(rendered)
                else:
                    print(rendered)
            if cu_count % 50 == 0:
                print(f"  scanned {cu_count} CUs, found {found_total} so far",
                      file=sys.stderr)
    print(f"done: scanned {cu_count} CUs, emitted {found_total} class definitions",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
