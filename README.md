# Factorio reverse-engineering & native modding toolkit

Tools, scripts, and harnesses for reading and modifying the Factorio 2.0
engine. **This repo is just the toolkit** — the game install and the RE
artifacts it produces live in sibling directories of this repo and are
not committed.

## Workspace layout

The toolkit assumes a workspace with this structure:

```
<workspace>/
├── factorio/                 # standalone Factorio install — gitignored
│   ├── bin/x64/factorio      #   engine binary (unstripped, DWARF-rich, 2.0.76)
│   ├── data/                 #   vanilla + expansion Lua source (plain text)
│   ├── doc-html/             #   official Lua API docs
│   └── mods/  saves/  config/  factorio-current.log  ...
├── re/                       # RE artifacts derived from the binary — gitignored
│   ├── symbols/              #   ~86k demangled functions, per-class drilldowns
│   ├── strings/              #   event names, error messages, prototype keys
│   ├── dwarf/                #   source file map + compile units
│   │   └── structs/          #   inferred class layouts (auto-generated)
│   ├── lua-index/            #   per-mod Lua file index (points at factorio/data/)
│   ├── ghidra-project/       #   Ghidra workspace, factorio_standalone (~2.2 GB)
│   ├── ghidra-logs/
│   └── decompiled/           #   per-class Ghidra pseudocode output
├── blackcat/                 # your UPS mod (own git repo)
└── factorio-re-toolkit/      # ↓ THIS REPO ↓
    ├── README.md             #   this file
    ├── .gitignore
    ├── tools/
    │   ├── ghidra/                # Ghidra install (gitignored, bootstrap-installed)
    │   ├── ghidra-scripts/
    │   │   ├── DecompileToFiles.java  # nm defined.txt + regex → .c per function
    │   │   ├── decompile.sh           # wrapper; writes to <workspace>/re/decompiled/
    │   │   ├── RenameFunctions.java   # one-time rename pass: applies demangled
    │   │   │                          # names to every function in the project,
    │   │   │                          # eliminating FUN_<addr> in decompile output
    │   │   └── rename_functions.sh    # wrapper for the rename script
    │   ├── extract_dwarf_structs.py   # pyelftools DWARF struct dumper
    │   │                              # (not useful here; see "Struct layouts")
    │   ├── infer_struct_fields.py     # parses decompiled .c files, aggregates
    │   │                              # `*(T*)(this+0xN)` accesses → struct skeleton
    │   ├── infer_structs_for_all.sh   # runs the above over every per-class dir
    │   ├── auto_type_fields.py        # streams objdump on whole binary, applies
    │   │                              # strict rules to type each field with a
    │   │                              # confidence tier (high/medium/reject)
    │   ├── auto_type_all_classes.sh   # wrapper: runs auto_type_fields on every
    │   │                              # *.inferred.h, prints aggregate summary
    │   ├── annotate_xrefs_and_metrics.py  # adds caller/callee + size/complexity
    │   │                                  # comment block to every decompiled .c
    │   ├── build_vtables.py           # enumerates every C++ vtable from _ZTV*
    │   │                              # symbols, resolves each method-ptr slot,
    │   │                              # writes <Class>.h to re/vtables/
    │   ├── probe_field.sh             # interactive: deeper per-field inspection
    │   │                              # with disassembly + decompile + gdb cmds
    │   ├── partition_decompiled.py    # splits flat decompile output into
    │   │                              # per-class subdirs by leading symbol prefix
    │   └── annotate_decompiled.py     # prepends `source-file:line` headers to
    │                                  # each .c via addr2line; idempotent
    └── mods/native/          # native modding harness
        ├── README.md
        ├── CMakeLists.txt    # FACTORIO_BINARY → ../../../factorio/bin/x64/factorio
        ├── scripts/
        │   ├── gen_symbols.py         # nm parser → C++ symbol table at build time
        │   ├── symbol_filter.txt      # which demangled-substrings to expose
        │   └── run_factorio.sh        # launches game with the hook .so injected
        ├── src/              # runtime hooks (LD_PRELOAD + Zydis detour)
        │   ├── detour.cpp             # x86-64 detour, RIP-rel-aware via Zydis
        │   ├── detour_test.cpp        # offline tests for the detour engine
        │   ├── loader.cpp             # main-exe load-base resolution (PIE-aware)
        │   ├── hook_manager.cpp       # registry, parent-only install gating
        │   └── hooks/                 # one source file per hook
        │       └── example_map_update.cpp  # times Map::updateEntities() per-tick
        └── patches/          # static byte patches (disk-time modifications)
            ├── README.md
            ├── patches.toml           # declarative patch list — committed
            ├── patch_tool.py          # apply / revert / verify / status
            └── journal.json           # per-machine state — gitignored
```

## Path conventions inside the toolkit

Every script in this repo locates two roots at runtime:

- **`toolkit_root`** = `factorio-re-toolkit/` (where this README lives)
- **`workspace`** = `factorio-re-toolkit/..` (parent dir, not committed)

Scripts read tooling from `$toolkit_root/...` and read/write artifacts +
the game install from `$workspace/factorio/`, `$workspace/re/`, etc.
There is no hardcoded absolute path; the toolkit can be cloned into any
workspace as long as `factorio/` is a sibling.

## The three workflows

All commands below assume your cwd is `factorio-re-toolkit/`.

### 1. Read engine code (Ghidra decompile)

1. One-time import. Re-run if you ever wipe `<workspace>/re/ghidra-project/`:
   ```bash
   cd ..   # to <workspace>
   ./factorio-re-toolkit/tools/ghidra/support/analyzeHeadless \
     re/ghidra-project factorio_standalone \
     -import factorio/bin/x64/factorio
   cd factorio-re-toolkit
   ```
   Auto-imports DWARF; ~42 min; project name `factorio_standalone`.

   **One-time post-import readability pass** (3 sec, mutates the project):
   ```bash
   ./tools/ghidra-scripts/rename_functions.sh
   ```
   Reads `<workspace>/re/symbols/all.txt`, applies demangled names to every
   function, attaches the full signature as a plate comment. Idempotent.
   After this, decompile output uses `Map__updateEntities` (Ghidra rewrites
   `::` to `__` in C identifiers) instead of `FUN_<addr>` at call sites.
2. Decompile selected functions: `./tools/ghidra-scripts/decompile.sh <out-dir> <regex>`.

   Output dirs are conventionally under the workspace's `re/decompiled/`.
   The wrapper uses an absolute path internally so any `<out-dir>` works:
   ```bash
   ./tools/ghidra-scripts/decompile.sh ../re/decompiled/Entity     '^Entity::'
   ./tools/ghidra-scripts/decompile.sh ../re/decompiled/Inserter   '^Inserter::'
   ./tools/ghidra-scripts/decompile.sh ../re/decompiled/UpdateLoop '::update\(\)|updateEntities'
   ```

   Each function lands as one `.c` file with a header comment showing the
   original demangled signature and address. Ghidra honors the imported
   DWARF, so types and parameter names come from Wube's debug info.

   For a flat batch run that you partition afterwards (one Ghidra startup
   per session is much faster):
   ```bash
   ./tools/ghidra-scripts/decompile.sh ../re/decompiled/_batch \
     '^(Entity|CraftingMachine|Inserter|MiningDrill|...)::'
   python3 ./tools/partition_decompiled.py ../re/decompiled/_batch ../re/decompiled --move
   rmdir ../re/decompiled/_batch
   ```

3. **Annotate with source file:line headers** (recommended after every
   decompile pass):
   ```bash
   ./tools/annotate_decompiled.py
   ```

4. **Annotate with cross-references and function metrics** (also
   recommended; ~60 sec one-time pass):
   ```bash
   ./tools/annotate_xrefs_and_metrics.py
   ```
   Streams `objdump -d` once, builds the call graph from direct `call`
   instructions and direct `jmp`-as-tailcall instructions, computes per-
   function size/basic-block/cyclomatic metrics, and prepends a comment
   block to every `.c` file. Idempotent — re-running strips the previous
   block and emits a fresh one. Sample header after this pass:
   ```c
   // Map::createSurface(...)
   // Address (file VMA assuming load=0): 0x1feccb0

   // ==== xrefs + metrics (auto-generated, deterministic) ====
   // SIZE      : 2288 bytes (0x8f0)
   // BBS       : 136      CYCLOMATIC: 60
   // CALLERS   : 5
   //   - Planet::getOrCreateSurface()
   //   - Map::importSurfaces(Map&, ImportSurfacesParameters const&)
   //   - SpacePlatform::createSurface(...)
   //   - LuaGameScript::luaCreateSurface(lua_State*)
   //   - MapEditorActionHandler::CreateSurface(...)
   // CALLEES   : 28 direct  +  0 tailcall  +  1 external  +  2 indirect
   //   direct:
   //     - operator delete(void*, unsigned long)
   //     - __cxa_allocate_exception
   //     - ...
   //   indirect: 2 call(s) through function pointer or vtable slot —
   //             see re/vtables/<Class>.h to resolve.
   // ==== end xrefs + metrics ====
   ```
   Every annotation is derived deterministically from instruction encodings
   (a `call rel32` is bytes; the target is a fact). Indirect calls are
   counted but never resolved here — see `build_vtables.py` for those.

5. **Enumerate vtables** (one-time, ~5 sec):
   ```bash
   ./tools/build_vtables.py
   ```
   For every C++ class with virtual methods (every `_ZTV<class>` symbol
   in the binary), reads the vtable's bytes directly and resolves each
   method pointer through `nm`. Emits `<workspace>/re/vtables/<Class>.h`,
   one per class. Layout follows the Itanium C++ ABI (slot 0 = offset_to_top,
   slot 1 = typeinfo, slot 2+ = method pointers in declaration order).
   Sample (`re/vtables/MiningDrill.h`):
   ```c
   // Vtable for `MiningDrill`
   // VMA: 0x380c5b0    Slots: 604    Methods: 602    Unresolved: 0
   struct MiningDrill_vtable {
       /* slot  0   +0x00   offset_to_top */ ptrdiff_t  offset_to_top;  // = 0
       /* slot  1   +0x08   typeinfo      */ void*      typeinfo;       // = 0x399eaf0
       /* slot  2   +0x10   method        */ void*      slot_10;  // -> Entity::getDump[abi:cxx11]() const
       /* slot  3   +0x18   method        */ void*      slot_18;  // -> Targetable::isAlarmValid(...) const
       /* slot  5   +0x28   method        */ void*      slot_28;  // -> MiningDrill::~MiningDrill()
       /* slot 11   +0x58   method        */ void*      slot_58;  // -> MiningDrill::draw(DrawQueue&) const
       ...
   };
   ```
   When a `.c` file shows `(**(code**)(*plVar1 + 0x58))(plVar1)`, look up
   slot at byte offset 0x58 in the relevant `<Class>.h` to resolve the
   virtual method. Wube engine is heavily virtual — Factorio's standalone
   build has 3,932 vtables, and `MiningDrill` alone exposes 602 methods.
   Runs `addr2line` in batch over every `.c` file under
   `<workspace>/re/decompiled/`, prepends a comment block with the source
   file, line number, and any inlined-call chain Wube's DWARF preserved.
   Idempotent — re-runnable; skips already-annotated files unless `--force`.

   Sample annotated header:
   ```c
   // Map::registerEntityByUnitNumber(unsigned long, Entity*)
   // Address (file VMA assuming load=0): 0x1607040
   // ------------------------------------------------------------
   // ANNOTATED: source     : .../src/Map/Map.cpp:2551
   // addr2line fn  : Map::registerEntityByUnitNumber(unsigned long, Entity*)
   // ------------------------------------------------------------
   ```
   With inlining info when present:
   ```c
   // ANNOTATED: source     : .../src/Util/Targeter.cpp:113
   // addr2line fn  : Inserter::clearPickupTarget()
   // Inlined into  :
   //                 <- .../src/Entity/Inserter.cpp:659  (clearPickupTarget)
   ```

### 2. Modify engine behavior at runtime (LD_PRELOAD hooks)

1. Identify the symbol(s) you want — grep `re/symbols/functions.txt`.
2. Add the demangled signature substring to `mods/native/scripts/symbol_filter.txt`.
3. Drop a hook file under `mods/native/src/hooks/`. Pattern:
   ```cpp
   #include "hook_manager.hpp"

   namespace {
     using OrigFn = ReturnT (*)(ThisT*, ArgT...);
     OrigFn g_orig = nullptr;

     ReturnT my_hook(ThisT* self, ArgT... args) {
       /* ... your code ... */
       return g_orig(self, args...);
     }

     void install() {
       g_orig = factorio_hooks::install_named_hook(
         "ClassName::methodName(", &my_hook);
     }
   }
   FACTORIO_HOOK_REGISTER(my_hook, install);
   ```
4. Build:
   ```bash
   cd mods/native && cmake -S . -B build && cmake --build build -j
   ```
5. Launch:
   ```bash
   ./mods/native/scripts/run_factorio.sh
   ```
   Stderr (and `factorio/factorio-current.log`) show `[factorio_hooks] ...`
   lines: load message, install summary with one entry per registered hook,
   plus whatever your hook prints.

The detour replaces the function's first ≥14 bytes (decoded to instruction
boundaries by Zydis) with an absolute JMP into your hook. Displaced bytes
go into a trampoline that resumes the original code; RIP-relative operands
and short branches are re-encoded for the new location. `g_orig` points to
that trampoline, so you can pass-through, modify args, replace the behavior
entirely, or skip the call.

Hooks install only in the main `factorio` process — fork-exec helpers
(sprite loader, updater check, asset downloader) silently skip. Init
ordering uses GCC `init_priority(101)` on `AutoRegister` objects so they
populate the registry before the unprioritized installer fires.

### 3. Modify engine bytes on disk (static patches)

For changes that should apply without injection — NOPs, branch flips,
constants, or anything in early-init code that runs before `LD_PRELOAD`
constructors:

```bash
cd mods/native/patches

# author: add a [[patch]] block to patches.toml (see patches/README.md)

./patch_tool.py status              # what's in the toml + what's applied
./patch_tool.py verify              # check expect_bytes match the binary
./patch_tool.py --dry-run apply     # preview without writing
./patch_tool.py apply               # write + journal + .orig backup
./patch_tool.py revert              # restore from journal
```

`patch_tool.py` defaults the binary to `<workspace>/factorio/bin/x64/factorio`
and the symbol table to `<workspace>/re/symbols/defined.txt`. Override with
`--binary <path>` and `--symbols <path>` if your layout differs.

It resolves symbol substrings via the symbol table, translates VMAs to file
offsets through ELF program headers, verifies `expect_bytes` before any
write, and stores a sha256-stamped journal so revert is exact.

## Address conventions (important)

There are four "addresses" in play for any function. Pick the right one
for the tool you're using:

- **File VMA** (what `nm` and `objdump` show): `Map::updateEntities` = `0x2568ce0`. Treat as load-base-0. This is what `re/symbols/*` records.
- **File offset within the ELF**: `0x2567ce0` for the same function — the `.text` segment maps file offset `0xfe1000` → VMA `0xfe2000`, so file-offset = VMA − `0x1000` for code. Used by `patch_tool.py` (which translates via ELF program headers, so you don't have to do this by hand).
- **Ghidra address**: image base `0x100000` is added to the file VMA → `0x2668ce0`. The decompile script reads our nm output and converts automatically.
- **Runtime virtual address**: per-process load base from `dl_iterate_phdr` (ASLR-randomized) plus the file VMA. Hook framework computes this at `.so` init.

If you're moving an address between tools, remember which space it's in.

## Struct layouts

Wube's Clang build used `-fno-standalone-debug`: function signatures are in
DWARF but **class member layouts are not**. The Unity CUs contain 6M DIEs
each, zero of which are `DW_TAG_structure_type` for Wube classes — only
stdlib/3rd-party types have layout info.

Instead of DWARF extraction, derive layouts from decompiled code:

```bash
# decompile the class (one of the workflow 1 commands above)
./tools/ghidra-scripts/decompile.sh ../re/decompiled/<Class> '^<Class>::'

# infer fields by aggregating *(T*)(this+0xN) accesses
python3 ./tools/infer_struct_fields.py ../re/decompiled/<Class> <Class>
```

Or batch-infer for every class already decompiled (writes to
`<workspace>/re/dwarf/structs/`):
```bash
./tools/infer_structs_for_all.sh
```

### Auto-typing fields with confidence tiers (machine-readable fact source)

`infer_struct_fields.py` is a *guess* about types — Ghidra's decompiler
inferred them from a few accesses, and that's what got recorded.
`auto_type_fields.py` is a *measurement*: it streams `objdump -d` on the
whole binary, watches every memory access touching each inferred offset
across all `<Class>::*` methods, and applies strict rules to assign a
type with an explicit confidence tier:

```bash
./tools/auto_type_all_classes.sh        # ~60 sec; one objdump pass total
```

Output: `<workspace>/re/dwarf/structs/<Class>.auto.h`, one per class,
with every field annotated:

```c
struct Inserter {
    /*+0x0048  width:8B  82×mov + 3×add + 1×cmp        conf:high*/    int64_t   f_48;   // arithmetic observed → integer
    /*+0x0098  width:1B  10×movzx + 1×cmp              conf:high*/    uint8_t   f_98;   // movzx → unsigned
    /*+0x01b8  width:8B  14×mov + 2×cmp + 1×add        conf:high*/    int64_t   f_1b8;
    /*+0x0030  width:mixed 8B×644/16B×2  640×mov+5×lea conf:medium*/  uint64_t  f_30;   // 100% qword by count, 2 outlier xmm copies
    /*+0x01d0  width:mixed 8B×31/4B×3/16B×2            conf:reject*/  char[?]   f_1d0;  // contradictory widths
    ...
};
```

**Trust rules** (also stamped into each generated header):

| `conf:` tier | What it means | What an agent should do |
|---|---|---|
| `high` | Operand size and (where applicable) signedness derived from machine code with no contradictions | Use the type as given. No further verification needed. |
| `medium` | One dominant interpretation but minor disagreements (e.g. 95%+ qword), OR 8B with no arithmetic (pointer-vs-int unresolvable from static analysis alone) | Use as a working hypothesis. Verify with `gdb` before writing code that depends on type kind (e.g. dereferencing it as a pointer). |
| `reject` | Mixed widths or contradictory accesses, or no accesses at all | Treat as raw bytes (`char[?]`). Do **not** assume any typed interpretation. |

**Conservatism is the design.** When in doubt, the script downgrades — it
never claims a type it can't prove. Real numbers across the 18 inferred
classes (770 fields):

```
TOTALS    high=101 (13%)   medium=255 (33%)   reject=414 (54%)
```

Most fields end up `reject`. That is the correct outcome — `Map`'s methods
touch dozens of foreign objects (`Surface*`, `Entity*` held in r12-r15),
and the same offset on different objects pollutes the evidence. The
script can't disambiguate, so it doesn't try.

**Why the format helps AI agents specifically.** Every comment carries
the evidence rollup (`82×mov + 3×add + 1×cmp`), the operand width
(`width:8B`), and the confidence tier (`conf:high`). An agent reading the
header knows the conclusion *and* its derivation in one place, without
having to re-derive from raw decompile output every time it touches the
class. The `f_<offset>` placeholder names stay opaque; rename them in a
hand-curated `<Class>.h` alongside the auto file when meanings are
understood. Both files use the same offset annotation, so renaming a
field never loses its underlying-memory provenance.

**Re-run conditions.** Run `auto_type_all_classes.sh` after:
- a new Ghidra decompile pass (which regenerated `*.inferred.h`)
- a Wube binary update (offsets and instruction patterns shift)
- you add new classes to `re/dwarf/structs/`

The pass is idempotent — re-running just rewrites the `.auto.h` files.

Current state of `re/dwarf/structs/`: 18 inferred headers covering the
hot path. Field counts give a rough sense of class complexity:

| Class           | Methods | Inferred fields | Notes |
|---|---|---|---|
| `Character`        | 194 | 177 | player avatar state |
| `MiningDrill`      | 105 | 144 | per-instance drill state |
| `Inserter`         |  99 |  96 | inserter state |
| `CraftingMachine`  | 124 |  70 | base for assemblers/furnaces |
| `Player`           |  34 |  56 | controller for `Character` |
| `Surface`          |  86 |  55 | one planet/platform |
| `TrainStop`        |  44 |  35 | |
| `Map`              |  35 |  32 | top-level world container |
| `Train`            |  22 |  31 | |
| `Entity`           | 597 |  25 | base; many fields are in derived classes |
| `LuaGameScript`    | 332 |  17 | the Lua API's `game` global |
| `LuaInventory`     |  51 |  11 | |
| `LuaEntity`        | 525 |   3 | wrapper: `+0x30` is the underlying `Entity*` (780 of 525×N method bodies dereference it) |
| `LuaSurface`/...   | …   |   2-3 | similar wrapper pattern |

Sample output excerpt (`re/dwarf/structs/Map.inferred.h`):
```
struct Map {
    /*+0x0018*/ ulong f_18;                 // 22 accesses — hot counter
    /*+0x04c0*/ _Rb_tree_node_base f_4c0;   // embedded std::map sentinel
    /*+0x04d0*/ _Rb_tree_node_base * f_4d0;
    /*+0x07c0*/ long f_7c0;                 // entity registry root
    ...
};
```

As you understand fields, rename `f_18` → `entity_count` in a curated copy
and use those names in hooks. The inference script is a starting point,
not ground truth — verify before committing to a name.

### Verifying a single field's true type

Before labeling `Class::f_<offset>` as a specific type, run:

```bash
./tools/probe_field.sh <ClassName> <offset_hex>             # static checks
./tools/probe_field.sh <ClassName> <offset_hex> --gdb       # also print gdb cmds
```

This runs three independent verifications:

1. **Instruction widths**: disassembles every `<ClassName>::*` method and
   reports each unique mnemonic + operand size that touches the offset.
   Tells you `qword/dword/word/byte` (size) and `movsx`/`movzx` (signed vs
   unsigned) with certainty.
2. **Decompiled access patterns**: greps `re/decompiled/<ClassName>/` for
   every `*(T*)(this+offset)` expression — shows how Ghidra typed the
   accesses based on flow.
3. **gdb runtime probe** (with `--gdb`): emits the gdb command file you
   paste against an attached factorio process. Reads the field at four
   widths plus pointer/float interpretations so you can see which one
   contains a sensible value.

**Decision rules:**

| Probe result | What it means |
|---|---|
| All accesses use one width (e.g. all `qword ptr`) | Confident — label as that size |
| All `movzx` for the size | Unsigned of that size |
| All `movsx` / `movsxd` | Signed of that size |
| All `movss` or `movsd` (xmm dest) | `float` / `double` |
| Mixed widths at the same offset | Union / packed struct / bitfield — **leave as `f_<offset>`** |
| `mov qword ptr` writes only (no arithmetic) | Pointer — confirm with gdb if address looks like `0x7f...` |
| `lea` only | Address-of (the offset is the start of a sub-struct or array) |

Caveat: the static check matches `<offset>` across all methods of the
class, including accesses through pointers other than `this`. If a
`Map::foo()` method touches `Surface::+0x18` via a `Surface*`, that hit
shows up in the Map probe. Cross-check by looking at the example lines —
ones with `[rdi+...]` are most likely the actual `this` field; others
may be false positives.

## Filesystem note

`/home/default/` is mounted on **eCryptfs** with `Namelen=143` (encrypted filenames eat extra bytes). The decompile script truncates basenames to 120 chars + 8-char hash; everything else fits. If you ever extend the workspace, watch for "File name too long" errors with templated stdlib names.

## Verifying the modded binary is running

Three independent indicators, in increasing latency:

1. **Stderr at launch.** `[factorio_hooks] factorio_hooks loaded (pid=N)` followed by `installing M hook(s) in main factorio process` and one `detour: 0x... -> 0x... (trampoline 0x..., displaced N src / M dst bytes)` per hook. If these are absent, no hooks. If `installing 0 hook(s)`, the registry is empty (build issue or missing `FACTORIO_HOOK_REGISTER` macro).
2. **Logfile.** Same lines also appear in `factorio/factorio-current.log` (Factorio mirrors stderr there). `tail -f factorio/factorio-current.log | grep factorio_hooks` from a second terminal works mid-game.
3. **Per-tick instrumentation.** `example_map_update.cpp` emits `Map::updateEntities tick=1024 avg=N.us this=N.us` every 1024 ticks (~17 sec at 60 UPS) once a save is loaded. Real number from a recent run: `tick=1024 avg=4354.6us this=1133.4us` — i.e., 4.35 ms/tick spent in the entity update loop.

In-game UI doesn't change unless a hook explicitly modifies it. Adding a
window-title or chat-message hook is a small follow-up if you want a
visible indicator in the game itself.

## Limitations to keep in mind

| Constraint | What to do |
|---|---|
| No engine source ships → can't rebuild the game | Hook live, or static-patch the binary; don't try to reconstruct a buildable tree |
| Decompiled pseudocode ≠ source | Read it for understanding, copy algorithms by hand into your hooks |
| Ghidra DWARF importer drops C++ namespaces from function names (sees `postUpdate`, not `Map::postUpdate`) | The decompile script bypasses Ghidra's name index — it filters our nm-derived `re/symbols/defined.txt` and looks up functions by address |
| No DWARF struct layouts for Wube classes (`-fno-standalone-debug`) | Use `tools/infer_struct_fields.py` against decompiled code; verify with gdb on a live session |
| Inlined/devirtualized functions have no callable address | Hook the caller or callee instead |
| Functions <14 bytes can't be patched | Pick a different hook point |
| RIP-relative prologues | Handled: detour.cpp uses Zydis to decode instruction boundaries and re-encode RIP-relative disp32 + short branches in the trampoline. Verified by `mods/native/build/detour_test`. |
| Factorio fork-execs helpers (sprite loader, updater, mod-portal asset fetcher) — they inherit `LD_PRELOAD` | `is_main_factorio_process()` in `hook_manager.cpp` filters: helpers silently skip install. Only the real game logs and patches. |
| Multiplayer determinism rejects diverging clients | Client-side logging/profiling/UI is fine; for gameplay changes every peer needs the patched binary |
| Wube updates change addresses | Re-run `cmake --build mods/native/build` to regenerate `factorio_symbols.cpp`; hook source is name-based and survives. Re-run nm dump: `nm --demangle --defined-only --format=bsd factorio/bin/x64/factorio > re/symbols/defined.txt`. Existing static patches must be `revert`ed first. |

## Bootstrap from scratch

Set up a fresh workspace from a clean clone. Assumes `factorio/` is
already in place as a sibling of this repo:

```
<workspace>/
├── factorio/                  # game install you placed here
└── factorio-re-toolkit/       # git clone of this repo
```

From `<workspace>/`:
```bash
cd factorio-re-toolkit

# 1. nm symbol tables (~10 sec, writes to <workspace>/re/)
mkdir -p ../re/{symbols,dwarf,strings,lua-index,decompiled,ghidra-logs}
nm --demangle ../factorio/bin/x64/factorio > ../re/symbols/all.txt
nm --demangle --defined-only --format=bsd ../factorio/bin/x64/factorio \
   > ../re/symbols/defined.txt
awk '$2~/^[TtWwiu]$/{$1=""; $2=""; sub(/^  /,""); print}' \
   ../re/symbols/defined.txt > ../re/symbols/functions.txt

# 2. Ghidra (one-time download into tools/, ~42 min headless import)
cd tools
curl -L -o ghidra.zip "$(curl -sSL \
  https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest \
  | python3 -c 'import sys,json;d=json.load(sys.stdin); \
                 [print(a["browser_download_url"]) for a in d["assets"] \
                  if a["name"].endswith(".zip")]')"
unzip -q ghidra.zip && ln -sfn ghidra_*_PUBLIC ghidra && rm ghidra.zip
cd ..
(cd .. && factorio-re-toolkit/tools/ghidra/support/analyzeHeadless \
   re/ghidra-project factorio_standalone \
   -import factorio/bin/x64/factorio)

# 3. Native hook harness (Zydis fetched via CMake, ~1 min first build)
cmake -S mods/native -B mods/native/build
cmake --build mods/native/build -j
./mods/native/build/detour_test     # offline tests for the detour engine

# 4. Optional: batch-decompile + struct inference for hot classes
./tools/ghidra-scripts/decompile.sh ../re/decompiled/_batch \
  '^(Map|Entity|EntityPrototype|CraftingMachine|Inserter|MiningDrill|LuaEntity|Surface|Train|TrainStop|Character|Player|LuaSurface|LuaForce|LuaGameScript|LuaPlayer|LuaTrain|LuaInventory|LuaControl|LuaBootstrap)::'
python3 ./tools/partition_decompiled.py ../re/decompiled/_batch ../re/decompiled --move
rmdir ../re/decompiled/_batch
./tools/infer_structs_for_all.sh
```

Required tools: gcc 13+ / g++ 13+, cmake 3.20+, Java 21+, python3.11+
with `pyelftools` (`pip3 install --user pyelftools`), plus standard
binutils (`nm`, `objdump`, `readelf`, `strings`, `c++filt`). No sudo
needed; Ghidra installs into `tools/`.
