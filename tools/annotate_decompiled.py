#!/usr/bin/env python3
"""Prepend source-file:line annotations to every decompiled .c file in
<workspace>/re/decompiled/.

For each .c file, the existing header looks like:

    // Map::updateEntities()
    // Address (file VMA assuming load=0): 0x2568ce0
    // Address in this Ghidra project:     0x2668ce0

After this script, the file gets a small block of additional context
prepended (after the existing header):

    // ---------------------------------------------------------------
    // Source     : src/Map/Map.cpp:2555 (best-effort, from DWARF .debug_line)
    // Inlined    : (none) | OR a chain like
    //              <- inlined into Map.cpp:2620
    //              <- inlined into Game.cpp:840
    // ---------------------------------------------------------------

Implementation notes:
- We use addr2line in BATCH MODE: feed all addresses on stdin, parse the
  output. This is roughly 1000x faster than spawning addr2line per file.
- Idempotent: skips files that already contain the annotation marker.
- Safe: writes via tmp + replace so a crash mid-write can't corrupt files.

Layout:
    <workspace>/factorio-re-toolkit/tools/annotate_decompiled.py   (this)
    <workspace>/factorio/bin/x64/factorio                          (binary)
    <workspace>/re/decompiled/<Class>/*.c                          (input/output)

Usage:
    ./tools/annotate_decompiled.py [--dir <dir>] [--binary <path>]
"""
from __future__ import annotations
import argparse
import re
import subprocess
import sys
from pathlib import Path


HEADER_ADDR_RE = re.compile(
    r"^// Address \(file VMA assuming load=0\):\s*0x([0-9a-fA-F]+)\s*$",
    re.MULTILINE)
ANNOTATION_MARKER = "// ANNOTATED: source"


def parse_args() -> argparse.Namespace:
    repo = Path(__file__).resolve().parents[1]   # factorio-re-toolkit/
    workspace = repo.parent                      # workspace/
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", type=Path,
                    default=workspace / "re/decompiled",
                    help="root directory of decompiled .c files")
    ap.add_argument("--binary", type=Path,
                    default=workspace / "factorio/bin/x64/factorio")
    ap.add_argument("--force", action="store_true",
                    help="re-annotate files even if the marker is present")
    return ap.parse_args()


def collect_files(root: Path) -> list[tuple[Path, int, str]]:
    """Return [(file_path, vma, original_text), ...] for every .c file with
    a parseable address header. Skips files that already have the
    annotation marker unless --force was passed."""
    out: list[tuple[Path, int, str]] = []
    for f in root.rglob("*.c"):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        m = HEADER_ADDR_RE.search(text)
        if not m:
            continue
        vma = int(m.group(1), 16)
        out.append((f, vma, text))
    return out


def run_addr2line(binary: Path, vmas: list[int]) -> dict[int, list[tuple[str, int, str]]]:
    """Run addr2line in batch mode. Returns {vma: [(file, line, function), ...]}.
    The list has multiple entries when the address is in an inlined chain
    (-i flag). Innermost first."""
    if not vmas:
        return {}
    cmd = ["addr2line", "-e", str(binary), "-f", "-C", "-i", "-a"]
    addr_input = "\n".join(f"0x{v:x}" for v in vmas) + "\n"
    res = subprocess.run(cmd, input=addr_input, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"addr2line failed: {res.stderr}", file=sys.stderr)
        return {}

    # Output format with -i -a -f:
    #   0xADDR
    #   function_name
    #   path/to/file.cpp:LINE
    #   [function_name_inlined_caller       ] <- present when -i finds inlined chain
    #   [path/to/file.cpp:LINE_inlined_caller]
    #   ...
    # New address starts with "0x" prefix on a line by itself.
    lines = res.stdout.splitlines()
    by_addr: dict[int, list[tuple[str, int, str]]] = {}
    cur_addr: int | None = None
    pending_func: str | None = None
    for raw in lines:
        line = raw.rstrip()
        if line.startswith("0x") and " " not in line:
            try:
                cur_addr = int(line, 16)
                pending_func = None
                by_addr.setdefault(cur_addr, [])
                continue
            except ValueError:
                pass
        if cur_addr is None:
            continue
        if pending_func is None:
            pending_func = line
            continue
        # This line is "file:line"
        path, sep, ln = line.rpartition(":")
        if sep != ":":
            pending_func = None
            continue
        try:
            lineno = int(ln) if ln.isdigit() else 0
        except ValueError:
            lineno = 0
        by_addr[cur_addr].append((path, lineno, pending_func))
        pending_func = None
    return by_addr


def format_annotation(entries: list[tuple[str, int, str]]) -> str:
    if not entries:
        return ANNOTATION_MARKER + "     : (addr2line returned no info)\n"
    # First entry is the innermost (the actual address). Subsequent entries
    # show the inlining chain back out to the leaf caller.
    head_path, head_line, head_func = entries[0]
    head_path_short = _shorten(head_path)
    out = [
        "// " + "-" * 60,
        f"{ANNOTATION_MARKER}     : {head_path_short}:{head_line}",
    ]
    if head_func and head_func != "??":
        out.append(f"// addr2line fn  : {head_func}")
    if len(entries) > 1:
        out.append("// Inlined into  :")
        for path, lineno, func in entries[1:]:
            short = _shorten(path)
            tag = f"{short}:{lineno}"
            if func and func != "??":
                tag += f"  ({func})"
            out.append(f"//                 <- {tag}")
    out.append("// " + "-" * 60)
    return "\n".join(out) + "\n"


def _shorten(path: str) -> str:
    # Wube paths look like /tmp/factorio-build-wtM46l/Clang/FinalSteamReleasex64/Agui/Unity1.cpp.
    # Trim the build-prefix noise so the comment is readable.
    for prefix in (
        "/tmp/factorio-build-",
        "/tmp/_fbuild.tmp/",
        "/tmp/tmp.",
    ):
        idx = path.find(prefix)
        if idx >= 0:
            after = path[idx + len(prefix):]
            # Drop the random hash dir component
            parts = after.split("/", 2)
            if len(parts) >= 2:
                return ".../" + "/".join(parts[1:])
    return path


def annotate(file_path: Path, original: str, annotation: str, force: bool) -> bool:
    if ANNOTATION_MARKER in original and not force:
        return False
    if force and ANNOTATION_MARKER in original:
        # Strip previous annotation block (between two `// ----` lines that
        # straddle the marker)
        original = _strip_previous_annotation(original)
    # Insert annotation right after the existing 3-line header block (which
    # ends with the first blank line).
    lines = original.splitlines(keepends=True)
    insert_at = 0
    for i, ln in enumerate(lines):
        if ln.strip() == "" and i > 0:
            insert_at = i + 1
            break
    new_text = "".join(lines[:insert_at]) + annotation + "".join(lines[insert_at:])
    tmp = file_path.with_suffix(file_path.suffix + ".tmp")
    tmp.write_text(new_text)
    tmp.replace(file_path)
    return True


def _strip_previous_annotation(text: str) -> str:
    # Remove the block from the previous --- line through the next --- line
    # surrounding the marker.
    lines = text.splitlines(keepends=True)
    out = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("// ----") and i + 1 < len(lines) and ANNOTATION_MARKER in lines[i + 1]:
            # find closing "// ----"
            j = i + 1
            while j < len(lines) and not lines[j].startswith("// ----"):
                j += 1
            i = j + 1  # skip closing line
            continue
        out.append(ln)
        i += 1
    return "".join(out)


def main() -> int:
    args = parse_args()
    if not args.dir.is_dir():
        print(f"no such dir: {args.dir}", file=sys.stderr)
        return 1
    if not args.binary.is_file():
        print(f"no such binary: {args.binary}", file=sys.stderr)
        return 1

    files = collect_files(args.dir)
    if not files:
        print(f"no annotatable .c files under {args.dir}", file=sys.stderr)
        return 0

    needs = [(f, v, t) for (f, v, t) in files
             if args.force or ANNOTATION_MARKER not in t]
    print(f"scanning {len(files)} files; {len(needs)} need annotation")
    if not needs:
        return 0

    addrs = sorted({v for _, v, _ in needs})
    print(f"running addr2line on {len(addrs)} unique addresses...")
    info = run_addr2line(args.binary, addrs)

    written = 0
    for f, vma, text in needs:
        ann = format_annotation(info.get(vma, []))
        if annotate(f, text, ann, args.force):
            written += 1
    print(f"annotated {written} files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
