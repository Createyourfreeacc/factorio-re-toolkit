#pragma once
#include "detour.hpp"
#include <functional>
#include <vector>

namespace factorio_hooks {

// Each registered hook is invoked at .so load time, after we have a usable
// load base for the main executable.
struct HookRegistration {
  const char* name;
  std::function<void()> install;
};

// Static registry. Hook source files (under src/hooks/) call register_hook()
// from a global initializer.
void register_hook(HookRegistration reg);

// Installs every registered hook. Called from the .so constructor.
void install_all_hooks();

// True if THIS process is the main Factorio executable (vs a forked helper
// like the sprite loader). Use to gate any per-process initialization.
bool is_main_factorio_process_public();

// For convenience in hook source files: resolve symbol substring + install
// detour with the given hook function. Returns the trampoline pointer cast to
// FnPtr, or nullptr on failure.
template <typename FnPtr>
FnPtr install_named_hook(const char* symbol_substring, FnPtr hook,
                         DetourHandle* handle_out = nullptr);

// Helper: macro-style registration. Place at file scope:
//   FACTORIO_HOOK_REGISTER([] { /* installer body */ });
struct AutoRegister {
  AutoRegister(const char* name, std::function<void()> fn);
};

// init_priority(101) puts this AutoRegister in .init_array.101 — the
// lowest user priority bucket — which runs BEFORE the unprioritized
// installer in hook_manager.cpp. The macro applies to every hook TU.
#define FACTORIO_HOOK_REGISTER(NAME, BODY) \
  static factorio_hooks::AutoRegister __attribute__((init_priority(101))) \
      _fh_autoreg_##NAME{ #NAME, BODY };

}  // namespace factorio_hooks

// Template definition follows after declaration so users can include this
// header from hooks.
#include "hook_manager.tcc"
