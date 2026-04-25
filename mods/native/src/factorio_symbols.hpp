#pragma once
#include <cstddef>
#include <cstdint>

namespace factorio_hooks {

struct SymbolEntry {
  const char* demangled;
  const char* mangled;
  std::uint64_t offset;  // file VMA assuming load base 0; add process load base at runtime
};

extern const SymbolEntry kSymbolTable[];
extern const std::size_t kSymbolTableSize;

// Linear search by substring of demangled signature. Small N (per filter list);
// not perf-critical (called once per hook at startup).
const SymbolEntry* find_symbol(const char* demangled_substring);

} // namespace factorio_hooks
