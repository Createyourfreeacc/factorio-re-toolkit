# Factorio native modding harness

LD_PRELOAD-injected `.so` that detours arbitrary engine functions by mangled
or demangled symbol name. Lets you intercept, replace, instrument, or extend
any C++ function in the Factorio binary — including internal symbols that
aren't in `.dynsym`.

## How it works

1. **Symbol resolution at build time.** `scripts/gen_symbols.py` runs `nm`
   on `bin/x64/factorio` and emits a C++ table of `(demangled, mangled,
   file_offset)` triples for every symbol matching a pattern in
   `scripts/symbol_filter.txt`.
2. **Load base lookup at runtime.** On `.so` constructor, `loader.cpp` uses
   `dl_iterate_phdr` to find the main executable's load base (Factorio is
   PIE so this is non-zero and randomized per run).
3. **Detour install.** For each registered hook, the symbol's runtime
   address = `load_base + file_offset`. `detour.cpp` overwrites the first
   14 bytes of that function with `movabs rax, hook_addr; jmp rax`, saving
   the original bytes into a freshly allocated RWX trampoline that resumes
   the original code path. The trampoline pointer is what your hook calls
   to invoke the original.
4. **Process exit unhooks.** Optional; right now the patches are leaked at
   exit since the process is shutting down anyway.

## Build

```bash
cd mods/native
cmake -S . -B build
cmake --build build -j
```

This regenerates `build/generated/factorio_symbols.cpp` from
`scripts/symbol_filter.txt` whenever the filter or the script changes.

## Run

```bash
./scripts/run_factorio.sh
```

This wraps the launcher with `LD_PRELOAD=./build/libfactorio_hooks.so`.
Hooks self-install on `.so` load. Tail stderr for `[factorio_hooks]` lines.

## Add a new hook

1. List the symbol's demangled signature substring in
   `scripts/symbol_filter.txt`. Discover symbols with:
   ```bash
   grep -i 'somekeyword' ../../re/symbols/functions.txt
   ```
2. Create a file under `src/hooks/`. Pattern:
   ```cpp
   #include "hook_manager.hpp"
   #include "log.hpp"

   namespace {
     using FnType = ReturnT (*)(ThisT*, ArgT...);
     FnType g_original = nullptr;

     ReturnT hooked(ThisT* self, ArgT... args) {
       FH_LOG("hello from inside the engine");
       return g_original(self, args...);
     }

     void install() {
       g_original = factorio_hooks::install_named_hook(
         "ClassName::methodName(", &hooked);
     }
   }
   FACTORIO_HOOK_REGISTER(my_hook, install);
   ```
3. Rebuild. Hook auto-installs on next launch.

## Calling-convention reminder (SystemV x86-64)

For a non-static C++ member function `Class::method(A, B, C)`:
- `this`  → `rdi`
- arg `A` → `rsi`
- arg `B` → `rdx`
- arg `C` → `rcx`
- return  → `rax` (or memory if large struct)

Reflect this in your hook signature: `ReturnT (*)(Class*, A, B, C)`. The
mangled `_ZN5Class6methodEixxx` form encodes the same thing — let the
demangled signature you grepped guide the C++ types.

## Limits / footguns

- **Tiny functions**: 14-byte patch overwrites past end if the function is
  shorter. Don't hook trivial accessors. Pick a non-leaf function or hook
  its caller.
- **RIP-relative prologues**: the displaced bytes are copied verbatim into
  the trampoline. If the prologue contains a `MOV rax, [rip+disp]` or
  `LEA rax, [rip+disp]`, the trampoline references the wrong address. If
  you see weird crashes on a hooked function, this is the suspect — fix
  by hand-editing the trampoline displacement, or upgrade detour.cpp to
  use a real x86 length disassembler (zydis).
- **Multiplayer determinism**: any hook that changes simulation behavior
  will desync from a vanilla server. For client-side instrumentation
  (logging, profiling, UI overlays) this is fine. For changing game logic,
  every connected peer needs the same patched binary.
- **Steam / Wube updates**: replace `bin/x64/factorio`. Symbol offsets
  shift. Re-run cmake to regenerate the symbol table; existing hook source
  doesn't change because we look up by name.
- **Inlined / devirtualized functions**: if the compiler inlined the
  function you wanted, there's no callable address. Pick a different hook
  point (the caller or callee).
- **Anti-cheat**: vanilla Factorio has none. Wube's MP server simply
  rejects desyncing clients.
