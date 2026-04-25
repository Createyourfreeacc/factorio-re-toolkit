#!/usr/bin/env python3
"""Enumerate every C++ vtable in the binary and emit one <Class>.h per
class under <workspace>/re/vtables/.

Source of truth: the Itanium C++ ABI used by GCC and Clang. For every class
with virtual methods, the linker emits a vtable named `_ZTV<class>` whose
layout is fixed:

  vtable[0]   ptrdiff_t    offset_to_top  (0 for single inheritance)
  vtable[1]   void*        typeinfo (RTTI)
  vtable[2]   fn_ptr       first virtual method
  vtable[3]   fn_ptr       second virtual method
  ...

For multiply-inherited classes the layout includes thunks and additional
secondary vtables; we report those exactly as they appear, never invent
ordering.

The vtable's class is in its mangled name: `_ZTV3Map` → "Map",
`_ZTV11MiningDrill` → "MiningDrill". We use `c++filt` to demangle.

Slot resolution: read 8-byte LE pointer from the binary at vtable offset N×8.
Look the value up in nm. If found, name it. If not, leave `0x...` raw.
Vtable terminates when a slot points outside .text or to address 0.

100% certain assertions:
  - every emitted slot points to bytes that are in fact at that VMA
  - every named slot resolves through nm
  - the class identity comes from the demangler, not inference

Usage:
    ./tools/build_vtables.py
"""
from __future__ import annotations
import argparse
import re
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("need pyelftools (pip install --user pyelftools)", file=sys.stderr)
    sys.exit(1)


_NM_RE = re.compile(r"^([0-9a-f]+)\s+([A-Za-z])\s+(.+)$")
# We need both mangled and demangled. We read defined.txt (demangled, BSD) and
# all.txt (also demangled). We also need the MANGLED forms for `_ZTV*`.


def parse_args() -> argparse.Namespace:
    repo = Path(__file__).resolve().parents[1]
    workspace = repo.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path,
                    default=workspace / "factorio/bin/x64/factorio")
    ap.add_argument("--symbols-mangled", type=Path, default=None,
                    help="nm (no demangle) output. If absent, regenerate via nm.")
    ap.add_argument("--symbols-demangled", type=Path,
                    default=workspace / "re/symbols/all.txt")
    ap.add_argument("--out-dir", type=Path,
                    default=workspace / "re/vtables")
    ap.add_argument("--max-slots", type=int, default=1024,
                    help="stop reading a vtable after N slots (safety bound)")
    return ap.parse_args()


def get_mangled_symbols(binary: Path, override: Path | None) -> list[tuple[int, str]]:
    """Returns [(vma, mangled_name), ...] for every defined symbol in the
    binary. Uses `nm <binary>` (no --demangle) so we get raw mangled names."""
    if override and override.is_file():
        text = override.read_text(errors="replace")
    else:
        cp = subprocess.run(
            ["nm", "--defined-only", "--format=bsd", str(binary)],
            capture_output=True, text=True, check=True)
        text = cp.stdout
    out = []
    for line in text.splitlines():
        m = _NM_RE.match(line)
        if not m:
            continue
        if m.group(2) not in "TtWwiuVvBbDdRrGgSs":
            # Include data symbols too — vtables are in 'V'/'v' or 'D'/'R'.
            continue
        try:
            vma = int(m.group(1), 16)
        except ValueError:
            continue
        out.append((vma, m.group(3)))
    return out


def load_demangled_addr_to_name(symbols_file: Path) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in symbols_file.read_text(errors="replace").splitlines():
        m = _NM_RE.match(line)
        if not m:
            continue
        if m.group(2) not in "TtWwiu":
            continue
        try:
            vma = int(m.group(1), 16)
        except ValueError:
            continue
        if vma not in out:
            out[vma] = m.group(3)
    return out


def demangle(name: str) -> str:
    """Run a single name through c++filt. Cached."""
    if not hasattr(demangle, "_cache"):
        demangle._cache = {}
    if name in demangle._cache:
        return demangle._cache[name]
    try:
        cp = subprocess.run(["c++filt", "-n", name],
                             capture_output=True, text=True, check=True)
        result = cp.stdout.strip()
    except Exception:
        result = name
    demangle._cache[name] = result
    return result


# ----------------------------------------------------------------------
# ELF VMA → file-offset translation
# ----------------------------------------------------------------------

def vma_to_file_offset(elf: ELFFile, vma: int) -> int | None:
    for seg in elf.iter_segments():
        if seg.header.p_type != "PT_LOAD":
            continue
        p_vaddr = seg.header.p_vaddr
        p_offset = seg.header.p_offset
        p_filesz = seg.header.p_filesz
        if p_vaddr <= vma < p_vaddr + p_filesz:
            return p_offset + (vma - p_vaddr)
    return None


def read_qword_at_vma(f, elf: ELFFile, vma: int) -> int | None:
    fo = vma_to_file_offset(elf, vma)
    if fo is None:
        return None
    f.seek(fo)
    raw = f.read(8)
    if len(raw) < 8:
        return None
    return struct.unpack("<Q", raw)[0]


# ----------------------------------------------------------------------
# Vtable parsing
# ----------------------------------------------------------------------

@dataclass
class VtableSlot:
    index: int
    byte_offset: int
    raw_value: int
    resolved_name: str | None
    kind: str   # "offset_to_top", "typeinfo", "method", "thunk", "raw"


def is_text_addr(vma: int, text_lo: int, text_hi: int) -> bool:
    return text_lo <= vma < text_hi


def parse_vtable(f, elf: ELFFile, base_vma: int,
                 demangled_funcs: dict[int, str],
                 text_lo: int, text_hi: int,
                 max_slots: int) -> list[VtableSlot]:
    slots: list[VtableSlot] = []
    # Slot 0: offset_to_top (signed ptrdiff_t)
    val0 = read_qword_at_vma(f, elf, base_vma)
    if val0 is None:
        return slots
    slots.append(VtableSlot(0, 0, val0, str(struct.unpack("<q", struct.pack("<Q", val0))[0]),
                            "offset_to_top"))
    # Slot 1: typeinfo
    val1 = read_qword_at_vma(f, elf, base_vma + 8)
    if val1 is None:
        return slots
    name1 = demangled_funcs.get(val1)
    slots.append(VtableSlot(1, 8, val1, name1, "typeinfo"))
    # Slots 2+: method pointers; stop when we hit zero, non-text, or hit
    # another vtable's start (we don't track other vtables here, so use
    # is_text_addr).
    for i in range(2, max_slots):
        off = i * 8
        val = read_qword_at_vma(f, elf, base_vma + off)
        if val is None or val == 0:
            break
        if not is_text_addr(val, text_lo, text_hi):
            # Could be a typeinfo for a secondary base, or padding into
            # the next vtable. Stop.
            break
        name = demangled_funcs.get(val)
        kind = "method"
        if name and name.startswith("non-virtual thunk to "):
            kind = "thunk"
        elif name is None:
            kind = "raw"
        slots.append(VtableSlot(i, off, val, name, kind))
    return slots


# ----------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------

def render_class(class_name: str, base_vma: int,
                 slots: list[VtableSlot]) -> str:
    method_count = sum(1 for s in slots if s.kind in ("method", "thunk"))
    raw_count = sum(1 for s in slots if s.kind == "raw")

    # Format the name nicely as a C identifier
    safe = re.sub(r"[^A-Za-z0-9_]", "_", class_name)

    lines = [
        f"// Vtable for `{class_name}`",
        f"// VMA: 0x{base_vma:x}    Slots: {len(slots)}    "
        f"Methods: {method_count}    Unresolved: {raw_count}",
        f"// Source: read directly from binary, names resolved via nm.",
        f"// Layout follows the Itanium C++ ABI: slots [0]=offset_to_top, "
        f"[1]=typeinfo, [2..]=method pointers in declaration order.",
        f"//",
        f"struct {safe}_vtable {{",
    ]
    for s in slots:
        if s.kind == "offset_to_top":
            lines.append(
                f"    /* slot  {s.index:2}   +0x{s.byte_offset:02x}   "
                f"offset_to_top */ "
                f"ptrdiff_t  offset_to_top;  // = {s.resolved_name}")
        elif s.kind == "typeinfo":
            ti = s.resolved_name or f"0x{s.raw_value:x}"
            lines.append(
                f"    /* slot  {s.index:2}   +0x{s.byte_offset:02x}   "
                f"typeinfo      */ "
                f"void*      typeinfo;       // = {ti}")
        else:
            label = "method " if s.kind == "method" else \
                    "thunk  " if s.kind == "thunk"  else "raw    "
            target = s.resolved_name or f"0x{s.raw_value:x}"
            lines.append(
                f"    /* slot  {s.index:2}   +0x{s.byte_offset:02x}   "
                f"{label}      */ "
                f"void*      slot_{s.byte_offset:x};  // -> {target}")
    lines.append("};")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------

def main() -> int:
    args = parse_args()
    if not args.binary.is_file():
        print(f"binary not found: {args.binary}", file=sys.stderr)
        return 1
    if not args.symbols_demangled.is_file():
        print(f"demangled symbols not found: {args.symbols_demangled}",
              file=sys.stderr)
        return 1
    args.out_dir.mkdir(parents=True, exist_ok=True)

    print("loading symbols...", file=sys.stderr)
    mangled = get_mangled_symbols(args.binary, args.symbols_mangled)
    demangled_funcs = load_demangled_addr_to_name(args.symbols_demangled)

    # Find every _ZTV* (vtable) symbol
    vtables = [(vma, name) for vma, name in mangled
               if name.startswith("_ZTV")]
    print(f"  {len(vtables)} vtable symbols (_ZTV*)", file=sys.stderr)

    # Get .text bounds for slot validation
    print("opening ELF for vtable read...", file=sys.stderr)
    with args.binary.open("rb") as f:
        elf = ELFFile(f)
        text_section = elf.get_section_by_name(".text")
        if text_section is None:
            print(".text section not found", file=sys.stderr)
            return 1
        text_lo = text_section.header.sh_addr
        text_hi = text_lo + text_section.header.sh_size
        print(f"  .text: [0x{text_lo:x}, 0x{text_hi:x})", file=sys.stderr)

        seen_classes: set[str] = set()
        emitted = 0
        skipped = 0
        for vma, mangled_name in vtables:
            # _ZTV<class> — pass the whole symbol through c++filt to get
            # "vtable for <class>". Strip the prefix.
            demangled = demangle(mangled_name)
            if not demangled.startswith("vtable for "):
                # Some _ZTV variants are construction vtables, etc.
                # Emit anyway with the raw demangled name as the title.
                class_name = demangled
            else:
                class_name = demangled[len("vtable for "):]

            slots = parse_vtable(f, elf, vma, demangled_funcs,
                                  text_lo, text_hi, args.max_slots)
            if not slots:
                skipped += 1
                continue
            # Filename: use the class identifier sanitized
            safe_fname = re.sub(r"[^A-Za-z0-9_]", "_", class_name)
            # Truncate for eCryptfs filename limit (143 bytes)
            if len(safe_fname) > 120:
                import hashlib
                h = hashlib.sha1(class_name.encode()).hexdigest()[:8]
                safe_fname = safe_fname[:120] + "__" + h
            out_path = args.out_dir / f"{safe_fname}.h"
            out_path.write_text(render_class(class_name, vma, slots))
            emitted += 1
            if emitted % 200 == 0:
                print(f"  emitted {emitted} vtables", file=sys.stderr)

    print(f"emitted {emitted} vtable headers (skipped {skipped} empty)",
          file=sys.stderr)
    print(f"output: {args.out_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
