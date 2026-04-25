#include "hook_manager.hpp"
#include "log.hpp"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <limits.h>
#include <vector>

namespace factorio_hooks {

namespace {

std::vector<HookRegistration>& registry() {
  static std::vector<HookRegistration> r;
  return r;
}

// Decide whether THIS process is the main Factorio executable.
//
// Factorio fork-execs many short-lived helpers (the parallel sprite loader,
// updater check, mod-portal asset downloader). They all inherit our
// LD_PRELOAD and re-run the .so's constructors. We only want hooks to
// install in the actual game process.
bool is_main_factorio_process() {
  char buf[PATH_MAX];
  ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return false;
  buf[n] = '\0';
  // Exact suffix match on /bin/x64/factorio; helpers (xdg-open, ldconfig,
  // sh, etc.) won't have this path.
  static const char kSuffix[] = "/bin/x64/factorio";
  size_t lp = static_cast<size_t>(n);
  size_t ls = sizeof(kSuffix) - 1;
  if (lp < ls) return false;
  return std::memcmp(buf + lp - ls, kSuffix, ls) == 0;
}

std::atomic<bool> g_install_started{false};

void try_install_once() {
  bool expected = false;
  if (!g_install_started.compare_exchange_strong(expected, true)) return;
  if (!is_main_factorio_process()) {
    // Quietly do nothing in helper subprocesses.
    return;
  }
  FH_LOG("installing %zu hook(s) in main factorio process",
         registry().size());
  for (auto& reg : registry()) {
    FH_LOG("  -> %s", reg.name);
    try {
      reg.install();
    } catch (...) {
      FH_LOG("  ! exception while installing %s", reg.name);
    }
  }
  FH_LOG("hook installation complete (%zu hook(s))", registry().size());
}

}  // namespace

// Public alias so LateInitInstaller can call from outside the anon namespace.
bool is_main_factorio_process_public() { return is_main_factorio_process(); }

void register_hook(HookRegistration reg) {
  registry().push_back(std::move(reg));
}

// Each hook source file's static AutoRegister object constructs at .so load.
// Two cases:
//   * If hook_manager's static-init runs first (so registry is just freshly
//     created), we just queue and return — the destructor of the order
//     guard below will fire install_all_hooks once everyone is registered.
//   * If a hook's AutoRegister fires after our installer attribute, this
//     hook didn't make it. The order guard handles both.
AutoRegister::AutoRegister(const char* name, std::function<void()> fn) {
  registry().push_back({name, std::move(fn)});
}

void install_all_hooks() {
  try_install_once();
}

}  // namespace factorio_hooks

// GCC init order semantics:
//   1. Static objects with `init_priority(N)` run in increasing N order.
//   2. Static objects WITHOUT init_priority run AFTER all prioritized ones,
//      in definition/link order.
//
// So we make AutoRegister objects prioritized (run early), and our
// installer object unprioritized (runs last). By the time
// LateInitInstaller's constructor fires, every AutoRegister in every hook
// TU has already populated the registry — no matter which TU was linked
// first.
namespace {
struct LateInitInstaller {
  LateInitInstaller() {
    // Only announce + install in the main game process. Helper subprocs
    // (sprite loaders, updater, mod-portal asset fetcher) inherit our
    // LD_PRELOAD but should be silent.
    if (factorio_hooks::is_main_factorio_process_public()) {
      FH_LOG("factorio_hooks loaded (pid=%d)", getpid());
      factorio_hooks::install_all_hooks();
    }
  }
};

// No init_priority attribute → goes in the "default" bucket → runs LAST.
LateInitInstaller g_late_installer;
}  // namespace
