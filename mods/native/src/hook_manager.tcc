#pragma once
#include "loader.hpp"
#include "log.hpp"
#include <cstdint>

namespace factorio_hooks {

template <typename FnPtr>
FnPtr install_named_hook(const char* symbol_substring, FnPtr hook,
                         DetourHandle* handle_out) {
  std::uintptr_t target = resolve(symbol_substring);
  if (!target) {
    FH_LOG("install_named_hook: cannot resolve '%s'", symbol_substring);
    return nullptr;
  }
  DetourHandle h;
  if (!install_detour(reinterpret_cast<void*>(target),
                      reinterpret_cast<void*>(hook), h)) {
    FH_LOG("install_named_hook: detour failed for '%s'", symbol_substring);
    return nullptr;
  }
  if (handle_out) *handle_out = h;
  return reinterpret_cast<FnPtr>(h.trampoline);
}

}  // namespace factorio_hooks
