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
    │   │   ├── DecompileToFiles.java  # takes nm-derived defined.txt + regex,
    │   │   │                          # resolves file VMAs to Ghidra addresses,
    │   │   │                          # emits one .c file per matched function
    │   │   └── decompile.sh           # wrapper; writes to <workspace>/re/decompiled/
    │   ├── extract_dwarf_structs.py   # pyelftools DWARF struct dumper
    │   │                              # (not useful here; see "Struct layouts")
    │   ├── infer_struct_fields.py     # parses decompiled .c files, aggregates
    │   │                              # `*(T*)(this+0xN)` accesses → struct skeleton
    │   ├── partition_decompiled.py    # splits flat decompile output into
    │   │                              # per-class subdirs by leading symbol prefix
    │   └── infer_structs_for_all.sh   # runs infer_struct_fields.py over every
    │                                  # <workspace>/re/decompiled/<Class>/ dir
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
not ground truth — verify with `gdb` against a running session if you're
about to write to one.

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
