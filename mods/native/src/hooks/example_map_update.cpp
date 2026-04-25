// Sample hook: count and time calls to Map::updateEntities().
//
// Demonstrates the standard pattern:
//   - declare a function pointer for the original (filled by the trampoline)
//   - write a hook with the SAME ABI as the target
//   - register installer that resolves + detours

#include "hook_manager.hpp"
#include "log.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>

namespace {

// Map::updateEntities() — non-static member, takes implicit `this` (Map*).
// We don't know what `this` actually points to and don't need to; we treat
// it as opaque. Calling convention: SystemV x86-64, `this` in rdi.
//
// Signature in symbols/functions.txt:
//   Map::updateEntities()
using UpdateEntitiesFn = void (*)(void* /*this*/);

UpdateEntitiesFn g_original = nullptr;

std::atomic<std::uint64_t> g_call_count{0};
std::atomic<std::uint64_t> g_total_ns{0};

void hooked_update_entities(void* self) {
  auto t0 = std::chrono::steady_clock::now();
  if (g_original) g_original(self);
  auto t1 = std::chrono::steady_clock::now();
  auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
  std::uint64_t n = ++g_call_count;
  g_total_ns.fetch_add(ns, std::memory_order_relaxed);
  if ((n & 0x3FF) == 0) {  // every 1024 ticks
    auto total = g_total_ns.load(std::memory_order_relaxed);
    FH_LOG("Map::updateEntities tick=%lu avg=%.1fus this=%.1fus",
           static_cast<unsigned long>(n),
           (double)total / (double)n / 1000.0,
           (double)ns / 1000.0);
  }
}

void install() {
  g_original = factorio_hooks::install_named_hook(
      "Map::updateEntities()", &hooked_update_entities);
  if (!g_original) {
    FH_LOG("example_map_update: failed to install hook");
  }
}

}  // namespace

FACTORIO_HOOK_REGISTER(map_update_entities, install);
