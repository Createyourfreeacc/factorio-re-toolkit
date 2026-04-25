#pragma once
#include <cstdint>
#include <cstddef>

namespace factorio_hooks {

// Result of a successful install_detour call. `trampoline` lets you call the
// original function (the bytes that were displaced + a jump back into the
// target). `original_bytes` is a copy of the displaced bytes for uninstall.
struct DetourHandle {
  void* target = nullptr;          // address that was patched
  void* trampoline = nullptr;      // call this to invoke original behavior
  std::uint8_t original_bytes[16]{};
  std::size_t patch_size = 0;
};

// Patches `target_addr` so that calling it transfers control to `hook_addr`.
// Writes the displaced bytes into a freshly-allocated trampoline that resumes
// the original code and returns it via DetourHandle.trampoline.
//
// On x86-64 this writes a 14-byte absolute jump:
//   48 b8 <8 bytes addr>   movabs rax, hook_addr
//   ff e0                  jmp rax
//
// Returns true on success. Fails if mprotect can't make .text writable, or if
// disassembling the function prologue would split a multi-byte instruction
// (we use a coarse heuristic that accepts the patch as long as 14 bytes are
// available in the function and tolerates a slightly imperfect trampoline —
// for non-leaf hot functions in Factorio this is fine; tighten if needed).
bool install_detour(void* target_addr, void* hook_addr, DetourHandle& out);

// Reverts the patch in `h.target` using the saved bytes.
bool uninstall_detour(const DetourHandle& h);

} // namespace factorio_hooks
