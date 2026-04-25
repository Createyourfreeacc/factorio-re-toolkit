#!/usr/bin/env python3
"""Apply / revert / verify declarative static patches to the Factorio binary.

Reads patches.toml, resolves each symbol to a file offset via nm output,
verifies originals match `expect_bytes`, writes `new_bytes` in-place, and
records a per-patch backup journal so anything can be undone.

Commands:
  apply     write all patches (by default only the ones not currently applied)
  revert    restore bytes recorded in the journal
  status    print which patches are currently applied
  verify    cross-check: do the expected bytes appear at every target?

This tool NEVER writes to the binary without first verifying the original
bytes. It always keeps a `<binary>.orig` full backup on first run.

Usage:
  patch_tool.py [--binary <path>] [--symbols <path>] [--patches <path>]
                [--journal <path>] {apply,revert,status,verify} [--dry-run]
                [--name NAME ...]
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # py311+
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        print("need tomllib (python3.11+) or tomli", file=sys.stderr)
        sys.exit(1)

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.segments import Segment
except ImportError:
    print("need pyelftools (pip install pyelftools)", file=sys.stderr)
    sys.exit(1)


@dataclass
class Patch:
    name: str
    expect_bytes: bytes
    new_bytes: bytes
    comment: str
    symbol: str | None = None
    offset: int | None = None  # resolved at runtime

    def validate(self) -> None:
        if not self.name:
            raise ValueError("patch missing name")
        if len(self.expect_bytes) != len(self.new_bytes):
            raise ValueError(
                f"{self.name}: expect_bytes ({len(self.expect_bytes)}) and "
                f"new_bytes ({len(self.new_bytes)}) must have equal length")
        if not self.expect_bytes:
            raise ValueError(f"{self.name}: expect_bytes is empty")
        if self.symbol is None and self.offset is None:
            raise ValueError(
                f"{self.name}: must set either symbol= or offset_hex=")


@dataclass
class JournalEntry:
    name: str
    offset: int
    original_bytes: str    # hex
    patched_bytes: str     # hex
    symbol: str | None
    comment: str


@dataclass
class Journal:
    binary_sha256: str
    entries: list[JournalEntry] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> "Journal | None":
        if not path.exists():
            return None
        data = json.loads(path.read_text())
        entries = [JournalEntry(**e) for e in data.get("entries", [])]
        return cls(binary_sha256=data.get("binary_sha256", ""), entries=entries)

    def save(self, path: Path) -> None:
        d = {
            "binary_sha256": self.binary_sha256,
            "entries": [e.__dict__ for e in self.entries],
        }
        path.write_text(json.dumps(d, indent=2))


# -----------------------------------------------------------------------
# parsing + resolution
# -----------------------------------------------------------------------

def parse_hex_bytes(s: str) -> bytes:
    s = s.strip()
    if not s:
        return b""
    cleaned = s.replace(",", " ").split()
    try:
        return bytes(int(x, 16) for x in cleaned)
    except ValueError as e:
        raise ValueError(f"bad hex bytes: {s!r}") from e


def load_patches(path: Path) -> list[Patch]:
    raw = tomllib.loads(path.read_text())
    out: list[Patch] = []
    for p in raw.get("patch", []):
        patch = Patch(
            name=p["name"],
            expect_bytes=parse_hex_bytes(p["expect_bytes"]),
            new_bytes=parse_hex_bytes(p["new_bytes"]),
            comment=p.get("comment", ""),
            symbol=p.get("symbol"),
            offset=int(p["offset_hex"], 16) if "offset_hex" in p else None,
        )
        patch.validate()
        out.append(patch)
    return out


_NM_RE = re.compile(r"^([0-9a-f]+)\s+([A-Za-z])\s+(.+)$")


def resolve_symbol(symbol_substring: str, symbols_file: Path) -> int:
    """Return the file offset (VMA assuming load=0) matching a demangled
    signature substring. Errors if no match or multiple matches."""
    hits: list[tuple[int, str]] = []
    for line in symbols_file.read_text(errors="replace").splitlines():
        m = _NM_RE.match(line)
        if not m:
            continue
        t = m.group(2)
        if t not in "TtWwiu":
            continue
        name = m.group(3)
        if symbol_substring in name:
            hits.append((int(m.group(1), 16), name))
    if not hits:
        raise ValueError(f"no symbol matches {symbol_substring!r}")
    # Prefer exact match of the leading prefix (ignores "non-virtual thunk to"
    # adapter lines and other noise).
    exact = [h for h in hits if h[1].startswith(symbol_substring)]
    if len(exact) == 1:
        return exact[0][0]
    if len(exact) > 1:
        names = "\n  ".join(h[1] for h in exact)
        raise ValueError(
            f"{symbol_substring!r} matches multiple symbols:\n  {names}\n"
            "use a more specific substring or a full mangled name")
    if len(hits) == 1:
        return hits[0][0]
    names = "\n  ".join(h[1] for h in hits[:10])
    raise ValueError(f"{symbol_substring!r} matches multiple symbols:\n  {names}")


def vma_to_file_offset(binary: Path, vma: int) -> int:
    """Translate a VMA (as reported by nm) to a file offset by walking ELF
    program headers. Raises if the VMA isn't in any LOAD segment."""
    with binary.open("rb") as f:
        elf = ELFFile(f)
        for seg in elf.iter_segments():
            if seg.header.p_type != "PT_LOAD":
                continue
            p_vaddr = seg.header.p_vaddr
            p_offset = seg.header.p_offset
            p_filesz = seg.header.p_filesz
            if p_vaddr <= vma < p_vaddr + p_filesz:
                return p_offset + (vma - p_vaddr)
    raise ValueError(f"VMA 0x{vma:x} is not in any LOAD segment of {binary}")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# -----------------------------------------------------------------------
# operations
# -----------------------------------------------------------------------

def cmd_status(args) -> int:
    patches = load_patches(args.patches)
    journal = Journal.load(args.journal) or Journal(binary_sha256="")
    applied = {e.name for e in journal.entries}
    print(f"binary: {args.binary}")
    print(f"current sha256: {sha256_file(args.binary)}")
    print(f"journal sha256: {journal.binary_sha256 or '(no journal)'}")
    print(f"patches in {args.patches.name}: {len(patches)}")
    print(f"applied: {len(applied)}")
    for p in patches:
        mark = "[x]" if p.name in applied else "[ ]"
        print(f"  {mark} {p.name:<30s}  {p.comment}")
    return 0


def cmd_verify(args) -> int:
    """Check that each patch's expect_bytes actually appears at its target."""
    patches = _filter_by_names(load_patches(args.patches), args.name)
    with args.binary.open("rb") as f:
        data = f.read()
    bad = 0
    for p in patches:
        off = _resolve_offset(p, args.symbols, args.binary)
        actual = data[off:off + len(p.expect_bytes)]
        if actual == p.expect_bytes:
            print(f"  ok   {p.name}  @ 0x{off:x}")
        else:
            bad += 1
            print(f"  FAIL {p.name}  @ 0x{off:x}")
            print(f"       expected: {p.expect_bytes.hex(' ')}")
            print(f"       actual:   {actual.hex(' ')}")
    return 1 if bad else 0


def cmd_apply(args) -> int:
    patches = _filter_by_names(load_patches(args.patches), args.name)
    if not patches:
        print("no patches to apply")
        return 0

    current_sha = sha256_file(args.binary)
    journal = Journal.load(args.journal)
    if journal and journal.binary_sha256 and journal.binary_sha256 != current_sha:
        print(f"ERROR: binary sha256 {current_sha} "
              f"differs from journal sha256 {journal.binary_sha256}. "
              f"Use 'revert' first or delete the journal if you're sure.",
              file=sys.stderr)
        return 2
    if journal is None:
        journal = Journal(binary_sha256=current_sha)

    already = {e.name for e in journal.entries}
    to_apply = [p for p in patches if p.name not in already]
    if not to_apply:
        print("all named patches already applied")
        return 0

    # Full binary backup on first application (real runs only)
    orig_path = args.binary.with_suffix(args.binary.suffix + ".orig")
    if not orig_path.exists() and not args.dry_run:
        print(f"creating full backup: {orig_path}")
        shutil.copy2(args.binary, orig_path)

    # Resolve offsets and verify expect_bytes for every patch FIRST.
    with args.binary.open("rb") as f:
        data = bytearray(f.read())
    for p in to_apply:
        p.offset = _resolve_offset(p, args.symbols, args.binary)
        actual = bytes(data[p.offset:p.offset + len(p.expect_bytes)])
        if actual != p.expect_bytes:
            print(f"ERROR: {p.name} @ 0x{p.offset:x} expected "
                  f"{p.expect_bytes.hex(' ')} but found {actual.hex(' ')}. "
                  f"Aborting; no bytes written.", file=sys.stderr)
            return 3
    # Everyone verified. Apply.
    for p in to_apply:
        original = bytes(data[p.offset:p.offset + len(p.new_bytes)])
        data[p.offset:p.offset + len(p.new_bytes)] = p.new_bytes
        journal.entries.append(JournalEntry(
            name=p.name,
            offset=p.offset,
            original_bytes=original.hex(),
            patched_bytes=p.new_bytes.hex(),
            symbol=p.symbol,
            comment=p.comment,
        ))
        print(f"  wrote {p.name}  @ 0x{p.offset:x}  "
              f"{original.hex(' ')} -> {p.new_bytes.hex(' ')}")

    if args.dry_run:
        print("dry-run: not writing binary or journal")
        return 0

    # Write binary atomically: tmp file + replace
    tmp = args.binary.with_suffix(args.binary.suffix + ".tmp")
    tmp.write_bytes(bytes(data))
    tmp.chmod(args.binary.stat().st_mode)
    tmp.replace(args.binary)
    journal.binary_sha256 = sha256_file(args.binary)
    journal.save(args.journal)
    print(f"journal: {args.journal} (sha256 {journal.binary_sha256[:12]}...)")
    return 0


def cmd_revert(args) -> int:
    journal = Journal.load(args.journal)
    if not journal or not journal.entries:
        print("nothing to revert (no journal or empty)")
        return 0
    to_revert = journal.entries
    if args.name:
        wanted = set(args.name)
        to_revert = [e for e in journal.entries if e.name in wanted]
        if not to_revert:
            print(f"no matching entries in journal for {args.name}")
            return 0

    with args.binary.open("rb") as f:
        data = bytearray(f.read())
    kept: list[JournalEntry] = []
    for e in journal.entries:
        if e in to_revert:
            orig = bytes.fromhex(e.original_bytes)
            current = bytes(data[e.offset:e.offset + len(orig)])
            if current != bytes.fromhex(e.patched_bytes):
                print(f"  WARN {e.name} @ 0x{e.offset:x}: expected patched "
                      f"bytes not found — binary may have drifted. Skipping.")
                kept.append(e)
                continue
            data[e.offset:e.offset + len(orig)] = orig
            print(f"  reverted {e.name}  @ 0x{e.offset:x}")
        else:
            kept.append(e)

    if args.dry_run:
        print("dry-run: not writing binary or journal")
        return 0

    tmp = args.binary.with_suffix(args.binary.suffix + ".tmp")
    tmp.write_bytes(bytes(data))
    tmp.chmod(args.binary.stat().st_mode)
    tmp.replace(args.binary)
    journal.entries = kept
    journal.binary_sha256 = sha256_file(args.binary) if kept else ""
    journal.save(args.journal)
    return 0


# -----------------------------------------------------------------------
# helpers
# -----------------------------------------------------------------------

def _filter_by_names(patches: list[Patch], names: list[str] | None) -> list[Patch]:
    if not names:
        return patches
    wanted = set(names)
    unknown = wanted - {p.name for p in patches}
    if unknown:
        print(f"WARN: unknown patch names in filter: {sorted(unknown)}",
              file=sys.stderr)
    return [p for p in patches if p.name in wanted]


def _resolve_offset(p: Patch, symbols_file: Path, binary: Path) -> int:
    """Return the FILE OFFSET at which to patch. Inputs (symbol → nm VMA, or
    explicit offset_hex) are VMAs; we translate to file offsets here."""
    if p.offset is not None:
        vma = p.offset
    else:
        assert p.symbol is not None
        vma = resolve_symbol(p.symbol, symbols_file)
    return vma_to_file_offset(binary, vma)


def main() -> int:
    # __file__ = <workspace>/factorio-re-toolkit/mods/native/patches/patch_tool.py
    # parents[0]=patches, [1]=native, [2]=mods, [3]=factorio-re-toolkit, [4]=workspace
    workspace = Path(__file__).resolve().parents[4]
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", type=Path,
                    default=workspace / "factorio/bin/x64/factorio")
    ap.add_argument("--symbols", type=Path,
                    default=workspace / "re/symbols/defined.txt")
    ap.add_argument("--patches", type=Path,
                    default=Path(__file__).parent / "patches.toml")
    ap.add_argument("--journal", type=Path,
                    default=Path(__file__).parent / "journal.json")
    ap.add_argument("--name", action="append",
                    help="only operate on these named patches (can repeat)")
    ap.add_argument("--dry-run", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    sub.add_parser("verify")
    sub.add_parser("apply")
    sub.add_parser("revert")
    args = ap.parse_args()

    if args.cmd == "status":
        return cmd_status(args)
    if args.cmd == "verify":
        return cmd_verify(args)
    if args.cmd == "apply":
        return cmd_apply(args)
    if args.cmd == "revert":
        return cmd_revert(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
