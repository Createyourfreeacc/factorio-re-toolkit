#pragma once
#include <cstdint>

namespace factorio_hooks {

// Resolves the load base of the main executable (Factorio itself), so we can
// translate file VMAs from the static symbol table into process addresses.
//
// Returns 0 if the main executable cannot be located. Cached after first call.
std::uintptr_t main_exe_base();

// Returns the run-time address of `symbol_substring` (matched against the
// demangled signature). Returns 0 if not found in kSymbolTable or if the load
// base lookup failed.
std::uintptr_t resolve(const char* symbol_substring);

} // namespace factorio_hooks
