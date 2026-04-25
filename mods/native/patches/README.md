# Static binary patches

Declarative byte patches for `factorio/bin/x64/factorio`. Complement to the
runtime hook framework: use this when a change is small and should apply
without any `.so` injection — e.g. nopping out a check, flipping a branch,
changing a constant, or disabling an early-init call that runs before any
`LD_PRELOAD`-loaded constructor fires.

## Design

Each patch in `patches.toml` is a symbol-relative byte rewrite with:

- `name` — short identifier (used by journal + CLI)
- `symbol` OR `offset_hex` — where to write
- `expect_bytes` — what must be there first (defense against version drift)
- `new_bytes` — same length as `expect_bytes`

`patch_tool.py` keeps a per-workspace `journal.json` so any patch can be
reverted exactly. On first apply, it saves a full `factorio.orig` backup in
the same directory as the binary.

Safety invariants:
1. Every patch is verified against `expect_bytes` before any byte is
   written. If any entry fails verification, nothing is applied.
2. `expect_bytes` and `new_bytes` must be the same length — no insertions,
   no deletions. Keeps addresses of everything else stable.
3. The journal records the binary's sha256. A mismatch on subsequent
   `apply`/`revert` (e.g. Wube shipped an update) blocks the operation until
   you explicitly reconcile.
4. Writes go through a `.tmp` replace, so a crash mid-write can't leave a
   corrupt binary.

## CLI

```bash
# list patches and whether they're applied
./patch_tool.py status

# verify expect_bytes actually appear at every target in the current binary
./patch_tool.py verify

# apply everything in patches.toml
./patch_tool.py apply

# apply only selected patches
./patch_tool.py apply --name demo_nop_map_update --name other_patch

# dry-run: resolve + verify, print what would be written, don't touch binary
./patch_tool.py apply --dry-run

# revert
./patch_tool.py revert               # all
./patch_tool.py revert --name X Y    # selected
```

## Authoring a new patch

1. Pick a target. Look up its address with:
   ```bash
   grep 'YourClass::yourMethod' ../../re/symbols/defined.txt
   ```
2. Disassemble to find the bytes you care about:
   ```bash
   objdump -d --disassemble='YourClass::yourMethod(' --demangle \
       ../../factorio/bin/x64/factorio | head -40
   ```
3. Convert the bytes you want to overwrite to the hex `expect_bytes` / `new_bytes`.
4. Add an entry to `patches.toml`:
   ```toml
   [[patch]]
   name = "disable_intro"
   symbol = "Game::playIntroVideo()"
   expect_bytes = "55 48 89 e5"   # push rbp ; mov rbp,rsp
   new_bytes    = "c3 90 90 90"   # ret ; nop ; nop ; nop
   comment = "Skip the intro entirely"
   ```
5. `./patch_tool.py verify` to confirm expect_bytes match before you apply.
6. `./patch_tool.py apply --dry-run` to see exactly what would be written.
7. `./patch_tool.py apply` when ready.

## When to use this vs the hook framework

| Goal | Tool |
|---|---|
| Replace behavior of a function | hook framework (`src/hooks/`) |
| Instrument/time a function | hook framework |
| Skip a check (NOP a branch) | static patch |
| Change a constant (e.g. tick rate) | static patch |
| Flip a conditional (JE ↔ JNE) | static patch |
| Code that runs before your .so loads | static patch |
| Distribute to a friend with no build step | static patch |

The two combine freely: patches apply on disk, hooks apply at runtime. Use
whichever is least invasive.

## Limits

- **Function boundary only.** If your patch would span into another
  instruction Ghidra didn't recognize, verify first with `objdump -d` that
  the `expect_bytes` cover whole instructions. A partial-instruction patch
  will crash at execution.
- **Wube updates invalidate addresses.** `journal.json` records the sha256
  of the binary at apply time. After an update, revert, regenerate nm
  symbols (`nm --demangle --defined-only --format=bsd factorio/bin/x64/factorio
  > re/symbols/defined.txt`), then re-apply.
- **Steam clients re-verify files** on their install path. This is moot
  since you're using the standalone build.
- **`.orig` backup lives next to the binary.** Don't commit it.
