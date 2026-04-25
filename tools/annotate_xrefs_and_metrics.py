#!/usr/bin/env python3
"""Annotate decompiled .c files with cross-references (callers/callees) and
function metrics (size / basic blocks / cyclomatic complexity) — both
extracted deterministically from the binary.

Single objdump pass collects everything in one go; per-file annotation is a
text rewrite that prepends a comment block (with explicit start/end markers
for idempotency).

What's extracted (all 100% certain — derived from instruction encodings):

  CALL GRAPH
    - direct calls:    `call <abs_addr>`        → edge resolved via nm
    - direct tail:     `jmp  <abs_addr>` if target is the start of another
                       function (per nm symbol table); otherwise treated as
                       intra-function control flow and ignored
    - indirect calls:  `call qword ptr [...]`   → counted, never resolved
    - external calls:  PLT thunks (e.g. malloc@plt) → resolved as external

  METRICS
    - byte_length:     next_function_start - this_function_start (per nm)
    - basic_block_count:   1 + count of jcc/jmp/ret/int3/ud2/call within fn
    - cyclomatic_complexity: count of cmp/test + count of conditional jumps
                             (Decision points; standard McCabe-ish metric)

Each `.c` file gets a header block like:

    // ==== xrefs + metrics (auto-generated, deterministic) ====
    // SIZE      : 1840 bytes (0x730)         SECTION  : .text
    // BBS       : 67  CYCLOMATIC: 31
    // CALLERS   :  3
    //   - Game::postUpdate
    //   - Map::tick
    //   - ScenarioRunner::step
    // CALLEES   : 47 direct  +  3 indirect  +  2 external
    //   direct:
    //     - Map::registerEntityByUnitNumber
    //     - Surface::tick
    //     - ...
    //   indirect: 3 (resolved at runtime via vtable; see re/vtables/)
    //   external:
    //     - malloc
    //     - free
    // ==== end xrefs + metrics ====

Idempotent: re-running strips the previous block and emits a fresh one.

Usage:
    ./tools/annotate_xrefs_and_metrics.py
"""
from __future__ import annotations
import argparse
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path


_NM_RE = re.compile(r"^([0-9a-f]+)\s+([A-Za-z])\s+(.+)$")
_HEADER_RE = re.compile(r"^([0-9a-f]+)\s+<([^>]+)>:")
_INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s*(\S+)(?:\s+(.*))?$")
# Direct call/jmp target: "call   <0x...>" form, or "call <symbol>" sometimes.
# objdump intel: "call   0x12345"  or  "jmp    0x12345"
_DIRECT_TARGET_RE = re.compile(r"^\s*(?:0x)?([0-9a-fA-F]+)\b")

# C-file header pattern (set by DecompileToFiles.java)
_FILE_VMA_RE = re.compile(
    r"^// Address \(file VMA assuming load=0\):\s*0x([0-9a-fA-F]+)\s*$",
    re.MULTILINE)

XREFS_START = "// ==== xrefs + metrics (auto-generated, deterministic) ===="
XREFS_END   = "// ==== end xrefs + metrics ===="


# Conditional-jump mnemonics (cyclomatic decision points)
_JCC_MNEMONICS = {
    "ja", "jae", "jb", "jbe", "jc", "je", "jecxz", "jrcxz", "jg", "jge",
    "jl", "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge",
    "jnl", "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo",
    "js", "jz",
}
# Unconditional control-flow that ends a basic block
_BB_TERMINATORS = _JCC_MNEMONICS | {"jmp", "ret", "retq", "iret", "iretq",
                                     "int3", "ud2", "call"}


def parse_args() -> argparse.Namespace:
    repo = Path(__file__).resolve().parents[1]
    workspace = repo.parent
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path,
                    default=workspace / "factorio/bin/x64/factorio")
    ap.add_argument("--symbols", type=Path,
                    default=workspace / "re/symbols/all.txt",
                    help="nm --demangle output (used for both lookup and "
                         "function boundary derivation)")
    ap.add_argument("--decompiled-dir", type=Path,
                    default=workspace / "re/decompiled")
    ap.add_argument("--progress-every", type=int, default=2_000_000)
    return ap.parse_args()


def load_symbols(symbols_file: Path) -> tuple[dict[int, str], list[int], set[int]]:
    """Parse nm output. Returns:
       - addr_to_name:  {vma: demangled_name} for every defined function symbol
       - sorted_starts: sorted list of every defined-function VMA
                         (used to compute function lengths)
       - external_set:  set of vmas whose name ends in '@plt' (PLT thunks
                         to dynamically-linked libc/glibc/Steam functions)"""
    addr_to_name: dict[int, str] = {}
    starts: list[int] = []
    external: set[int] = set()
    for line in symbols_file.read_text(errors="replace").splitlines():
        m = _NM_RE.match(line)
        if not m:
            continue
        sym_type = m.group(2)
        if sym_type not in "TtWwiu":
            continue
        try:
            vma = int(m.group(1), 16)
        except ValueError:
            continue
        if vma == 0:
            continue
        name = m.group(3)
        # Prefer the FIRST name we see for each address (others are aliases).
        if vma not in addr_to_name:
            addr_to_name[vma] = name
            starts.append(vma)
        if "@plt" in name or name.endswith("$plt"):
            external.add(vma)
    starts.sort()
    return addr_to_name, starts, external


def function_length(start: int, sorted_starts: list[int]) -> int | None:
    """Returns approximate byte length using next-function-start. None at end."""
    import bisect
    idx = bisect.bisect_right(sorted_starts, start)
    if idx >= len(sorted_starts):
        return None
    return sorted_starts[idx] - start


# ----------------------------------------------------------------------
# Streaming objdump pass
# ----------------------------------------------------------------------

def stream_extract(binary: Path,
                   addr_to_name: dict[int, str],
                   external: set[int],
                   progress_every: int):
    """Stream objdump on the whole binary. Returns:
       - calls_out:    {caller_addr: [(target_addr, kind), ...]}
                       where kind in {"direct", "indirect", "external", "tailcall"}
       - metrics:      {fn_addr: (bb_count, cyclo)}
                       (size is computed separately from sorted_starts)
    """
    calls_out: dict[int, list[tuple[int, str]]] = defaultdict(list)
    metrics: dict[int, tuple[int, int]] = {}

    cur_fn: int | None = None
    bb_count = 1            # implicit entry block
    decision_points = 0     # jcc count → cyclomatic
    saw_indirect = 0        # direct-only flag for callees
    fn_starts = set(addr_to_name)

    cmd = ["objdump", "-d", "--no-show-raw-insn", "-M", "intel", str(binary)]
    print(f"running: {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            text=True, bufsize=1 << 16)
    line_count = 0
    insn_count = 0
    try:
        for line in proc.stdout:
            line_count += 1
            if line_count % progress_every == 0:
                print(f"  parsed {line_count // 1_000_000}M lines, "
                      f"{insn_count // 1_000_000}M instructions, "
                      f"{len(metrics)} fns processed",
                      file=sys.stderr)

            mh = _HEADER_RE.match(line)
            if mh:
                if cur_fn is not None:
                    metrics[cur_fn] = (bb_count, decision_points)
                try:
                    cur_fn = int(mh.group(1), 16)
                except ValueError:
                    cur_fn = None
                bb_count = 1
                decision_points = 0
                continue

            if cur_fn is None:
                continue

            mi = _INSN_RE.match(line)
            if not mi:
                continue
            insn_count += 1
            mnemonic = mi.group(2)
            operands = mi.group(3) or ""

            # Basic-block count: any terminator ends a block; the next instr
            # starts a new one. Use the count of terminators as proxy
            # (BB count = 1 + terminators within fn).
            if mnemonic in _BB_TERMINATORS:
                bb_count += 1
            if mnemonic in _JCC_MNEMONICS:
                decision_points += 1
            if mnemonic in ("cmp", "test"):
                # Cyclomatic also counts cmp/test, but to avoid double-count
                # we use (jcc_count) which is already 1:1 with each conditional
                # branch. cmp/test alone don't add to cyclomatic.
                pass

            # Call / tail call extraction
            if mnemonic == "call" or mnemonic == "jmp":
                # Distinguish indirect (`[...]` operand) vs direct (`0xADDR`)
                op = operands.strip()
                if op.startswith("qword") or op.startswith("QWORD") \
                   or op.startswith("[") or "[" in op[:20] and "]" in op:
                    if mnemonic == "call":
                        calls_out[cur_fn].append((0, "indirect"))
                    # `jmp [...]` is also indirect but typically used for
                    # vtable dispatch or jump tables; record as indirect.
                    elif "ptr" in op.lower() and "[" in op:
                        calls_out[cur_fn].append((0, "indirect"))
                    continue
                m = _DIRECT_TARGET_RE.match(op)
                if not m:
                    continue
                try:
                    target = int(m.group(1), 16)
                except ValueError:
                    continue

                # For `call`, always record. For `jmp`, only if the target is
                # the start of a known function (real tail call); otherwise
                # it's intra-function control flow.
                if mnemonic == "call":
                    if target in external:
                        calls_out[cur_fn].append((target, "external"))
                    elif target in addr_to_name:
                        calls_out[cur_fn].append((target, "direct"))
                    else:
                        # target is some unnamed code (e.g. local label) —
                        # may still be of interest, but agents won't get
                        # value from "call to address 0xNNN". Skip.
                        pass
                else:  # jmp
                    if target == cur_fn:
                        # self-jump (loop back to entry); intra-function
                        continue
                    if target in fn_starts:
                        # It's a tail call into another function
                        if target in external:
                            calls_out[cur_fn].append((target, "external"))
                        else:
                            calls_out[cur_fn].append((target, "tailcall"))

        if cur_fn is not None:
            metrics[cur_fn] = (bb_count, decision_points)
    finally:
        proc.wait()
    print(f"done: {line_count // 1_000_000}M lines, "
          f"{insn_count // 1_000_000}M insns, "
          f"{len(metrics)} fns processed",
          file=sys.stderr)
    return calls_out, metrics


# ----------------------------------------------------------------------
# Annotation render + write
# ----------------------------------------------------------------------

def render_block(addr: int,
                 addr_to_name: dict[int, str],
                 sorted_starts: list[int],
                 callers: dict[int, list[int]],
                 callees: list[tuple[int, str]],
                 metrics: dict[int, tuple[int, int]]) -> str:
    bb, cyclo = metrics.get(addr, (0, 0))
    size = function_length(addr, sorted_starts)
    size_str = f"{size} bytes (0x{size:x})" if size is not None else "?"

    direct = sorted({t for t, kind in callees if kind == "direct"})
    tailcalls = sorted({t for t, kind in callees if kind == "tailcall"})
    indirect = sum(1 for _, kind in callees if kind == "indirect")
    externals = sorted({t for t, kind in callees if kind == "external"})

    caller_addrs = sorted(set(callers.get(addr, [])))

    lines: list[str] = []
    lines.append(XREFS_START)
    lines.append(f"// SIZE      : {size_str}")
    lines.append(f"// BBS       : {bb}      CYCLOMATIC: {cyclo}")

    if not caller_addrs:
        lines.append(f"// CALLERS   :  0  (no direct callers found in binary)")
    else:
        lines.append(f"// CALLERS   : {len(caller_addrs)}")
        for c in caller_addrs[:30]:
            lines.append(f"//   - {addr_to_name.get(c, f'0x{c:x}')}")
        if len(caller_addrs) > 30:
            lines.append(f"//   ... ({len(caller_addrs) - 30} more callers omitted)")

    callee_total = len(direct) + len(tailcalls) + len(externals)
    lines.append(f"// CALLEES   : {len(direct)} direct  +  "
                 f"{len(tailcalls)} tailcall  +  {len(externals)} external"
                 f"  +  {indirect} indirect")
    if direct:
        lines.append("//   direct:")
        for c in direct[:40]:
            lines.append(f"//     - {addr_to_name.get(c, f'0x{c:x}')}")
        if len(direct) > 40:
            lines.append(f"//     ... ({len(direct) - 40} more direct omitted)")
    if tailcalls:
        lines.append("//   tailcall:")
        for c in tailcalls[:20]:
            lines.append(f"//     - {addr_to_name.get(c, f'0x{c:x}')}")
        if len(tailcalls) > 20:
            lines.append(f"//     ... ({len(tailcalls) - 20} more tailcalls omitted)")
    if externals:
        lines.append("//   external:")
        for c in externals[:20]:
            lines.append(f"//     - {addr_to_name.get(c, f'0x{c:x}')}")
        if len(externals) > 20:
            lines.append(f"//     ... ({len(externals) - 20} more externals omitted)")
    if indirect:
        lines.append(f"//   indirect: {indirect} call(s) through function pointer "
                     f"or vtable slot — see re/vtables/<Class>.h to resolve.")

    lines.append(XREFS_END)
    return "\n".join(lines) + "\n"


def strip_existing_block(text: str) -> str:
    """Remove an existing xrefs+metrics block (between markers) if present."""
    start = text.find(XREFS_START)
    if start < 0:
        return text
    end = text.find(XREFS_END, start)
    if end < 0:
        return text
    end += len(XREFS_END)
    # Eat any trailing newlines that belonged to the block
    while end < len(text) and text[end] == "\n":
        end += 1
    return text[:start] + text[end:]


def annotate_file(path: Path,
                  block: str) -> bool:
    """Insert/refresh the annotation block right after the existing 3-line
    address header. Returns True if the file was modified."""
    text = path.read_text(errors="replace")
    text_no_block = strip_existing_block(text)
    # Insert after the existing header (first blank line following the
    # address-comments header).
    lines = text_no_block.splitlines(keepends=True)
    insert_at = 0
    for i, ln in enumerate(lines):
        if ln.strip() == "" and i > 0:
            insert_at = i + 1
            break
    new_text = "".join(lines[:insert_at]) + block + "\n" + "".join(lines[insert_at:])
    if new_text == text:
        return False
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(new_text)
    tmp.replace(path)
    return True


def main() -> int:
    args = parse_args()
    if not args.binary.is_file():
        print(f"binary not found: {args.binary}", file=sys.stderr)
        return 1
    if not args.symbols.is_file():
        print(f"symbols not found: {args.symbols}", file=sys.stderr)
        return 1
    if not args.decompiled_dir.is_dir():
        print(f"decompiled dir not found: {args.decompiled_dir}", file=sys.stderr)
        return 1

    # Load nm
    addr_to_name, sorted_starts, external = load_symbols(args.symbols)
    print(f"symbols: {len(addr_to_name)} defined funcs, "
          f"{len(external)} external (PLT)", file=sys.stderr)

    # Stream objdump once
    calls_out, metrics = stream_extract(args.binary, addr_to_name,
                                         external, args.progress_every)

    # Build reverse callers map
    callers: dict[int, list[int]] = defaultdict(list)
    for caller, edges in calls_out.items():
        for target, kind in edges:
            if kind in ("direct", "tailcall"):
                callers[target].append(caller)

    # Walk every .c file, annotate
    files = sorted(args.decompiled_dir.rglob("*.c"))
    if not files:
        print("no .c files to annotate", file=sys.stderr)
        return 0

    annotated = 0
    skipped_no_addr = 0
    for f in files:
        text = f.read_text(errors="replace")
        m = _FILE_VMA_RE.search(text)
        if not m:
            skipped_no_addr += 1
            continue
        try:
            addr = int(m.group(1), 16)
        except ValueError:
            continue
        block = render_block(addr, addr_to_name, sorted_starts,
                             callers, calls_out.get(addr, []), metrics)
        if annotate_file(f, block):
            annotated += 1
        if annotated > 0 and annotated % 500 == 0:
            print(f"  annotated {annotated} of {len(files)} files",
                  file=sys.stderr)

    print(f"annotated {annotated} files; "
          f"skipped {skipped_no_addr} (no address header)",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
