#include "loader.hpp"
#include "factorio_symbols.hpp"
#include "log.hpp"

#include <cstring>
#include <link.h>
#include <unistd.h>

namespace factorio_hooks {

namespace {

uintptr_t g_main_base = 0;
bool g_main_base_resolved = false;

// dl_iterate_phdr callback: the FIRST entry corresponds to the main executable.
// Its dlpi_addr is the load offset (0 for non-PIE, runtime base for PIE).
int phdr_cb(struct dl_phdr_info* info, size_t /*size*/, void* data) {
  auto* out = static_cast<uintptr_t*>(data);
  // The first object in the iteration order is the main exe. Capture and stop.
  if (*out == 0) {
    *out = static_cast<uintptr_t>(info->dlpi_addr);
    // dlpi_name is empty string for the main exe; sanity check.
    if (info->dlpi_name && info->dlpi_name[0] != '\0') {
      // Not the main exe (some loaders put it later); keep iterating.
      *out = 0;
      return 0;
    }
    return 1;  // stop iteration
  }
  return 0;
}

}  // namespace

uintptr_t main_exe_base() {
  if (g_main_base_resolved) return g_main_base;
  uintptr_t base = 0;
  dl_iterate_phdr(phdr_cb, &base);
  g_main_base = base;
  g_main_base_resolved = true;
  if (base == 0) {
    FH_LOG("failed to locate main executable load base via dl_iterate_phdr");
  } else {
    FH_LOG("main exe load base: 0x%lx", static_cast<unsigned long>(base));
  }
  return base;
}

const SymbolEntry* find_symbol(const char* substr) {
  for (size_t i = 0; i < kSymbolTableSize; ++i) {
    if (std::strstr(kSymbolTable[i].demangled, substr) != nullptr) {
      return &kSymbolTable[i];
    }
  }
  return nullptr;
}

uintptr_t resolve(const char* symbol_substring) {
  const SymbolEntry* e = find_symbol(symbol_substring);
  if (!e) {
    FH_LOG("resolve: symbol not in table: %s", symbol_substring);
    return 0;
  }
  uintptr_t base = main_exe_base();
  if (base == 0) return 0;
  return base + e->offset;
}

}  // namespace factorio_hooks
