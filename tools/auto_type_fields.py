#!/usr/bin/env python3
"""Auto-type struct fields by gathering machine-code evidence per offset and
classifying with strict rules.

Approach (one-pass, fast):
  1. Build a map: function_VMA → class_name from re/symbols/defined.txt for
     every <Class> that has a <Class>.inferred.h.
  2. Build a map: class_name → set of inferred offsets.
  3. Stream `objdump -d` on the whole binary.
  4. Track which function we're in (objdump emits "0xADDR <name>:" headers).
  5. For each instruction, if we're inside a class-of-interest function and
     the instruction's memory operand offset is one we care about, record
     evidence (operand size, mnemonic, signedness, etc.).
  6. After the stream ends, classify per (class, offset) and emit
     <Class>.auto.h with confidence-stamped fields.

Single `objdump` invocation; total runtime is dominated by disassembly speed
(~30-90 seconds for the whole 233 MB Factorio binary).

Layout:
    <workspace>/factorio-re-toolkit/tools/auto_type_fields.py   (this)
    <workspace>/factorio/bin/x64/factorio
    <workspace>/re/symbols/defined.txt
    <workspace>/re/dwarf/structs/<Class>.inferred.h            (input)
    <workspace>/re/dwarf/structs/<Class>.auto.h                (output)

Usage:
    auto_type_fields.py            # process all classes (default)
    auto_type_fields.py --class Map
"""
from __future__ import annotations
import argparse
import re
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path


HIGH = "high"
MEDIUM = "medium"
REJECT = "reject"


# ----------------------------------------------------------------------
# Evidence container + classifier
# ----------------------------------------------------------------------

@dataclass
class Evidence:
    sizes: Counter = field(default_factory=Counter)
    mnemonics: Counter = field(default_factory=Counter)
    is_signed_extended: int = 0
    is_zero_extended: int = 0
    is_float_load: int = 0
    is_call_through: int = 0
    is_arithmetic: int = 0
    is_compare: int = 0
    is_lea: int = 0
    is_store: int = 0
    is_load: int = 0
    examples: list = field(default_factory=list)

    def total(self) -> int:
        return sum(self.sizes.values())


# Mnemonic categorization
_FLOAT_MNEMONICS = {
    "movss", "movsd", "movupd", "movups", "movdqu", "movdqa",
    "movapd", "movaps", "addsd", "addss", "subsd", "subss",
    "minss", "minsd", "maxss", "maxsd", "mulss", "mulsd",
    "divss", "divsd", "ucomiss", "ucomisd",
}
_ARITH_MNEMONICS = {
    "add", "sub", "imul", "mul", "inc", "dec", "neg",
    "shl", "shr", "sal", "sar", "rol", "ror",
}
_BITWISE_MNEMONICS = {"and", "or", "xor"}
_COMPARE_MNEMONICS = {"cmp", "test"}
_INDIRECT_BRANCH = {"call", "jmp"}


def width_from_line(operand_part: str) -> int | None:
    lc = operand_part.lower()
    if "xmmword" in lc and "ptr" in lc: return 16
    if "ymmword" in lc and "ptr" in lc: return 32
    if "qword"   in lc and "ptr" in lc: return 8
    if "dword"   in lc and "ptr" in lc: return 4
    if "word"    in lc and "ptr" in lc: return 2
    if "byte"    in lc and "ptr" in lc: return 1
    return None


def classify_mnemonic(mnemonic: str, ev: Evidence, operand_str: str):
    if mnemonic in _FLOAT_MNEMONICS:
        ev.is_float_load += 1
    if mnemonic in _ARITH_MNEMONICS:
        ev.is_arithmetic += 1
    if mnemonic in _BITWISE_MNEMONICS:
        # Bitwise ops on a memory location often indicate flag fields, but
        # they can apply to integers too. Don't count as arithmetic.
        pass
    if mnemonic in _COMPARE_MNEMONICS:
        ev.is_compare += 1
    if mnemonic == "lea":
        ev.is_lea += 1
    if mnemonic == "movzx":
        ev.is_zero_extended += 1
    elif mnemonic in ("movsx", "movsxd"):
        ev.is_signed_extended += 1
    if mnemonic in _INDIRECT_BRANCH:
        ev.is_call_through += 1
    if mnemonic == "mov":
        # Determine load vs store by which side has the [...].
        # operand_str is the part after the mnemonic.
        comma_at = operand_str.find(",")
        if comma_at > 0:
            left = operand_str[:comma_at].lower()
            if "ptr" in left or left.lstrip().startswith("["):
                ev.is_store += 1
            else:
                ev.is_load += 1


# ----------------------------------------------------------------------
# Verdict
# ----------------------------------------------------------------------

@dataclass
class Verdict:
    confidence: str
    type_str: str
    rationale: str
    width_summary: str


def classify(ev: Evidence) -> Verdict:
    total = ev.total()

    if total == 0 and ev.is_lea == 0:
        return Verdict(REJECT, "char[?]", "no accesses found",
                       "width:none")

    if total == 0:
        return Verdict(REJECT, "char[?]",
                       "lea-only access; field is sub-struct address",
                       f"width:lea-only  {ev.is_lea}×lea")

    size_parts = sorted(ev.sizes.items(), key=lambda x: -x[1])
    if len(size_parts) == 1:
        width_summary = f"width:{size_parts[0][0]}B"
    else:
        width_summary = "width:mixed " + "/".join(
            f"{s}B×{c}" for s, c in size_parts)

    top_mn = ev.mnemonics.most_common(4)
    rollup = " + ".join(f"{c}×{m}" for m, c in top_mn)
    if ev.is_lea > 0 and "lea" not in dict(top_mn):
        rollup += f" + {ev.is_lea}×lea"

    # Mixed widths
    if len(ev.sizes) > 1:
        dominant_size, dominant_count = max(ev.sizes.items(), key=lambda x: x[1])
        if dominant_count / total >= 0.95:
            ratio_pct = int(round(100 * dominant_count / total))
            return Verdict(MEDIUM,
                           _typename_for(dominant_size),
                           f"dominant width {dominant_size}B in {ratio_pct}% "
                           f"of {total} accesses",
                           f"{width_summary}  {rollup}")
        return Verdict(REJECT, "char[?]",
                       "mixed widths — likely union, packed struct, or "
                       "false positives across multiple objects",
                       f"{width_summary}  {rollup}")

    # Single width below minimum support
    if total < 2:
        return Verdict(REJECT, "char[?]",
                       f"only {total} access — below minimum support",
                       f"{width_summary}  {rollup}")

    size = next(iter(ev.sizes))

    # Float vs int
    if ev.is_float_load > 0:
        if ev.is_float_load == total:
            type_str = ("float" if size == 4
                        else "double" if size == 8
                        else _typename_for(size))
            return Verdict(HIGH, type_str,
                           f"all {total} accesses use float SSE instructions",
                           f"{width_summary}  {rollup}")
        return Verdict(REJECT, "char[?]",
                       "int and float accesses both observed",
                       f"{width_summary}  {rollup}")

    # 8-byte: pointer vs int
    if size == 8:
        if ev.is_call_through > 0 and ev.is_arithmetic == 0:
            return Verdict(HIGH, "void*",
                           f"called/jumped through this offset {ev.is_call_through}× "
                           f"with no arithmetic — likely function pointer or vtable slot",
                           f"{width_summary}  {rollup}")
        if ev.is_arithmetic > 0:
            return Verdict(HIGH, "int64_t",
                           f"arithmetic operations observed ({ev.is_arithmetic}×) — "
                           f"integer rather than pointer",
                           f"{width_summary}  {rollup}")
        return Verdict(MEDIUM, "uint64_t",
                       f"all {total} accesses 8B with no arithmetic; "
                       f"cannot statically distinguish pointer from int64",
                       f"{width_summary}  {rollup}")

    # 1B / 2B: signedness from movzx/movsx
    if size in (1, 2):
        if ev.is_signed_extended > 0 and ev.is_zero_extended == 0:
            return Verdict(HIGH,
                           "int8_t" if size == 1 else "int16_t",
                           f"{ev.is_signed_extended}× movsx — signed",
                           f"{width_summary}  {rollup}")
        if ev.is_zero_extended > 0 and ev.is_signed_extended == 0:
            return Verdict(HIGH,
                           "uint8_t" if size == 1 else "uint16_t",
                           f"{ev.is_zero_extended}× movzx — unsigned",
                           f"{width_summary}  {rollup}")
        if ev.is_signed_extended > 0 and ev.is_zero_extended > 0:
            return Verdict(REJECT, "char[?]",
                           "movsx and movzx both observed — sign ambiguous",
                           f"{width_summary}  {rollup}")
        return Verdict(MEDIUM,
                       "uint8_t" if size == 1 else "uint16_t",
                       f"all {total} accesses {size}B; no extension instructions to "
                       f"distinguish signed/unsigned — defaulting to unsigned",
                       f"{width_summary}  {rollup}")

    # 4B
    if size == 4:
        if ev.is_signed_extended > 0:
            return Verdict(HIGH, "int32_t",
                           f"{ev.is_signed_extended}× movsxd — signed",
                           f"{width_summary}  {rollup}")
        return Verdict(MEDIUM, "uint32_t",
                       f"all {total} accesses 4B; signedness ambiguous — "
                       f"defaulting to unsigned",
                       f"{width_summary}  {rollup}")

    # 16/32B vector
    if size in (16, 32):
        return Verdict(MEDIUM, f"char[{size}]",
                       f"all accesses {size}B vector loads — embedded array or SIMD chunk",
                       f"{width_summary}  {rollup}")

    return Verdict(REJECT, "char[?]", "unhandled case",
                   f"{width_summary}  {rollup}")


def _typename_for(size: int) -> str:
    return {
        1: "uint8_t", 2: "uint16_t", 4: "uint32_t",
        8: "uint64_t", 16: "char[16]", 32: "char[32]",
    }.get(size, "char[?]")


# ----------------------------------------------------------------------
# I/O helpers
# ----------------------------------------------------------------------

_NM_RE = re.compile(r"^([0-9a-f]+)\s+([A-Za-z])\s+(.+)$")
_INFERRED_RE = re.compile(
    r"^\s*/\*\+(0x[0-9a-fA-F]+)\*/\s+([^;]+?)\s+f_[0-9a-fA-F]+;.*$")


def parse_args() -> argparse.Namespace:
    repo = Path(__file__).resolve().parents[1]
    workspace = repo.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--class", dest="cls",
                    help="single class name (default: process all)")
    ap.add_argument("--binary", type=Path,
                    default=workspace / "factorio/bin/x64/factorio")
    ap.add_argument("--symbols", type=Path,
                    default=workspace / "re/symbols/defined.txt")
    ap.add_argument("--structs-dir", type=Path,
                    default=workspace / "re/dwarf/structs")
    ap.add_argument("--progress-every", type=int, default=2_000_000,
                    help="print progress every N input lines (default 2M)")
    return ap.parse_args()


def parse_inferred(inferred_h: Path) -> list[tuple[int, str]]:
    out = []
    for line in inferred_h.read_text(errors="replace").splitlines():
        m = _INFERRED_RE.match(line)
        if not m:
            continue
        out.append((int(m.group(1), 16), m.group(2).strip()))
    return out


def build_function_class_map(symbols_file: Path,
                              wanted_classes: set[str]
                              ) -> dict[int, str]:
    """vma → class_name for every function whose demangled name starts with
    one of the wanted class names followed by `::` or `<`."""
    out: dict[int, str] = {}
    sorted_classes = sorted(wanted_classes, key=len, reverse=True)
    for line in symbols_file.read_text(errors="replace").splitlines():
        m = _NM_RE.match(line)
        if not m:
            continue
        if m.group(2) not in "TtWwiu":
            continue
        name = m.group(3)
        for cls in sorted_classes:
            if name.startswith(cls + "::") or name.startswith(cls + "<"):
                try:
                    out[int(m.group(1), 16)] = cls
                except ValueError:
                    pass
                break
    return out


# ----------------------------------------------------------------------
# Streaming objdump pass
# ----------------------------------------------------------------------

# Header lines look like:  "0000000002568ce0 <Map::updateEntities>:"
_HEADER_RE = re.compile(r"^([0-9a-f]+)\s+<([^>]+)>:")

# Instruction line example (after --no-show-raw-insn):
#   "  2568cf3:	mov    QWORD PTR [r14+0x18],rdi"
_INSN_RE = re.compile(r"^\s*[0-9a-f]+:\s*(\S+)(?:\s+(.*))?$")

# Match any "[<reg>±0xNN]" form. Capture both the register and the offset.
_MEM_RE = re.compile(
    r"\[\s*([a-z0-9]+)(?:\s*\+\s*[a-z0-9]+\s*\*\s*\d+)?\s*([+\-])\s*(0x[0-9a-fA-F]+)\s*\]")

_THIS_REGS = {"rdi", "rbx", "rbp", "r12", "r13", "r14", "r15"}


def stream_disassemble(binary: Path,
                       fn_to_class: dict[int, str],
                       offsets_per_class: dict[str, set[int]],
                       progress_every: int,
                       ) -> dict[tuple[str, int], Evidence]:
    """Returns { (class, offset): Evidence }."""
    evidence: dict[tuple[str, int], Evidence] = defaultdict(Evidence)

    cmd = ["objdump", "-d", "--no-show-raw-insn", "-M", "intel", str(binary)]
    print(f"running: {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            text=True, bufsize=1 << 16)
    cur_class: str | None = None
    cur_offsets: set[int] | None = None

    line_count = 0
    inst_count = 0
    matched_count = 0

    try:
        for line in proc.stdout:
            line_count += 1
            if line_count % progress_every == 0:
                print(f"  parsed {line_count // 1_000_000}M lines, "
                      f"{inst_count // 1_000_000}M instructions, "
                      f"{matched_count} matched accesses",
                      file=sys.stderr)

            # Function header? Switch context.
            m = _HEADER_RE.match(line)
            if m:
                vma = int(m.group(1), 16)
                cls = fn_to_class.get(vma)
                cur_class = cls
                cur_offsets = offsets_per_class.get(cls) if cls else None
                continue

            if cur_class is None or not cur_offsets:
                continue

            # Instruction line?
            m = _INSN_RE.match(line)
            if not m:
                continue
            inst_count += 1
            mnemonic = m.group(1)
            operands = m.group(2) or ""

            # Find any memory operand referencing one of our offsets.
            for mem in _MEM_RE.finditer(operands):
                reg = mem.group(1)
                sign = mem.group(2)
                off_hex = mem.group(3)
                if sign == "-":
                    continue   # negative offsets aren't this->field
                # Apply the this-pointer heuristic: only register names that
                # plausibly hold `this`.
                if reg not in _THIS_REGS:
                    continue
                # Skip RIP-relative addresses
                if reg == "rip":
                    continue
                try:
                    off = int(off_hex, 16)
                except ValueError:
                    continue
                if off not in cur_offsets:
                    continue

                ev = evidence[(cur_class, off)]
                w = width_from_line(operands)
                if w is None:
                    if mnemonic == "lea":
                        ev.mnemonics[mnemonic] += 1
                        ev.is_lea += 1
                        if len(ev.examples) < 6:
                            ev.examples.append(line.rstrip())
                    continue
                ev.sizes[w] += 1
                ev.mnemonics[mnemonic] += 1
                classify_mnemonic(mnemonic, ev, operands)
                if len(ev.examples) < 6:
                    ev.examples.append(line.rstrip())
                matched_count += 1
                # An instruction has at most one memory operand for our
                # purposes; break after the first match.
                break
    finally:
        proc.wait()

    print(f"done: {line_count // 1_000_000}M lines, "
          f"{inst_count // 1_000_000}M instructions, "
          f"{matched_count} matched accesses",
          file=sys.stderr)
    return evidence


# ----------------------------------------------------------------------
# Output formatting
# ----------------------------------------------------------------------

def format_field_line(offset: int, verdict: Verdict, original_type: str) -> str:
    comment = f"/*+0x{offset:04x}  {verdict.width_summary}  conf:{verdict.confidence}*/"
    return (f"    {comment:<74} {verdict.type_str:<12} f_{offset:x};"
            f"  // was: {original_type}; {verdict.rationale}")


def render_class(cls: str, fields: list[tuple[int, str, Verdict]],
                 source_methods: int) -> str:
    counts = Counter(v.confidence for _, _, v in fields)
    total = len(fields)
    max_offset = max((o for o, _, _ in fields), default=0)
    header = (
        f"// AUTO-TYPED struct layout for `{cls}`\n"
        f"// Generated by tools/auto_type_fields.py\n"
        f"// Source: re/dwarf/structs/{cls}.inferred.h + machine-code analysis\n"
        f"// of {source_methods} {cls}::* methods. Max offset: 0x{max_offset:x}.\n"
        f"// Confidence summary: high={counts.get(HIGH, 0)}  medium={counts.get(MEDIUM, 0)}  "
        f"reject={counts.get(REJECT, 0)}  total={total}\n"
        f"//\n"
        f"// Each field comment carries:\n"
        f"//   /* +<offset>  width:<size>  <evidence rollup>  conf:<tier> */\n"
        f"// Trust rules:\n"
        f"//   conf:high   → operand size and (if applicable) signedness derived\n"
        f"//                 from machine code with no contradictions. Suitable\n"
        f"//                 for use without further verification.\n"
        f"//   conf:medium → one dominant interpretation but minor disagreements,\n"
        f"//                 OR 8B with no arithmetic (pointer-vs-int unresolvable\n"
        f"//                 statically). Verify with gdb before writing code that\n"
        f"//                 depends on the type kind.\n"
        f"//   conf:reject → mixed-width or contradictory accesses, or no\n"
        f"//                 accesses at all. Treat as raw bytes; do not assume\n"
        f"//                 a typed interpretation.\n"
        f"//\n"
        f"// Field names are placeholders (f_<offset>); rename in a hand-curated\n"
        f"// {cls}.h alongside this file when meanings are understood.\n"
        f"\n"
        f"struct {cls} {{\n"
    )
    body = "\n".join(format_field_line(off, v, orig)
                     for off, orig, v in fields)
    return header + body + "\n};\n"


# ----------------------------------------------------------------------
# Driver
# ----------------------------------------------------------------------

def main() -> int:
    args = parse_args()
    if not args.binary.is_file():
        print(f"binary not found: {args.binary}", file=sys.stderr)
        return 1
    if not args.symbols.is_file():
        print(f"symbols not found: {args.symbols}", file=sys.stderr)
        return 1
    if not args.structs_dir.is_dir():
        print(f"structs dir not found: {args.structs_dir}", file=sys.stderr)
        return 1

    # Load inferred headers
    if args.cls:
        inferred_files = [args.structs_dir / f"{args.cls}.inferred.h"]
    else:
        inferred_files = sorted(args.structs_dir.glob("*.inferred.h"))
    if not inferred_files:
        print("no inferred headers to process", file=sys.stderr)
        return 0

    fields_per_class: dict[str, list[tuple[int, str]]] = {}
    offsets_per_class: dict[str, set[int]] = {}
    for f in inferred_files:
        cls = f.name[: -len(".inferred.h")]
        fields = parse_inferred(f)
        if not fields:
            continue
        fields_per_class[cls] = fields
        offsets_per_class[cls] = {off for off, _ in fields}

    if not fields_per_class:
        print("no fields parsed from inferred headers", file=sys.stderr)
        return 0

    print(f"classes to process: {len(fields_per_class)}", file=sys.stderr)
    for cls in fields_per_class:
        print(f"  {cls}: {len(fields_per_class[cls])} fields", file=sys.stderr)

    # Build function-VMA → class map
    print(f"building function-class map from {args.symbols}", file=sys.stderr)
    fn_to_class = build_function_class_map(args.symbols, set(fields_per_class))
    print(f"  {len(fn_to_class)} functions span the wanted classes",
          file=sys.stderr)

    # Single-pass disassembly
    evidence = stream_disassemble(args.binary, fn_to_class,
                                  offsets_per_class, args.progress_every)

    # Render and emit per-class .auto.h
    for cls, fields in fields_per_class.items():
        # Count methods of this class for the header
        n_methods = sum(1 for c in fn_to_class.values() if c == cls)
        rendered_fields = []
        for off, orig in fields:
            ev = evidence.get((cls, off), Evidence())
            verdict = classify(ev)
            rendered_fields.append((off, orig, verdict))
        rendered = render_class(cls, rendered_fields, n_methods)
        out_path = args.structs_dir / f"{cls}.auto.h"
        out_path.write_text(rendered)
        counts = Counter(v.confidence for _, _, v in rendered_fields)
        print(f"  wrote {out_path.name}  "
              f"high={counts.get(HIGH, 0)} "
              f"medium={counts.get(MEDIUM, 0)} "
              f"reject={counts.get(REJECT, 0)}",
              file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
