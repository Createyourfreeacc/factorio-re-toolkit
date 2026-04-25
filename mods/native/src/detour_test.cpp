// Offline test driver for the detour engine.
//
// Compile-time standalone: builds a tiny executable that constructs a
// buffer of known instructions, installs a detour into it, verifies the
// hook fires, calls the trampoline to verify the original runs, and
// asserts the RIP-relative relocation happened correctly.
//
// This does NOT touch the Factorio binary. It just proves the engine
// handles a few representative prologues end-to-end.

#include "detour.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace fh = factorio_hooks;

namespace {

std::uint8_t* alloc_rx_page() {
  long ps = sysconf(_SC_PAGESIZE);
  auto* p = static_cast<std::uint8_t*>(
      mmap(nullptr, ps, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  return (p == MAP_FAILED) ? nullptr : p;
}

// Test 1: a simple stack-setup prologue (no RIP-relative).
// We install a hook and verify both the hook and the trampoline work.
int g_orig_called = 0;
int g_hook_called = 0;

using VoidFn = int (*)();

VoidFn g_tramp = nullptr;

int original_impl() {
  g_orig_called++;
  return 42;
}

int hook_impl() {
  g_hook_called++;
  int r = g_tramp();
  return r + 100;
}

int test_plain_prologue() {
  // Write a function that is: push rbp; mov rbp,rsp; mov eax, 42; pop rbp; ret; plus padding.
  std::uint8_t* code = alloc_rx_page();
  if (!code) { std::fprintf(stderr, "mmap failed\n"); return 1; }
  // Function body must be >= 14 bytes BEFORE any ret, so Zydis can relocate
  // a full prologue into the trampoline without hitting ret early.
  std::uint8_t body[] = {
    0x55,                                           // push rbp            (1)
    0x48, 0x89, 0xe5,                               // mov rbp, rsp        (3)
    0x48, 0x83, 0xec, 0x20,                         // sub rsp, 32         (4)
    0x48, 0xc7, 0x45, 0xf8, 0x00, 0x00, 0x00, 0x00, // movq [rbp-8], 0     (8) ← crosses byte 14
    0xb8, 0x2a, 0x00, 0x00, 0x00,                   // mov eax, 42         (5)
    0x48, 0x83, 0xc4, 0x20,                         // add rsp, 32         (4)
    0x5d,                                           // pop rbp             (1)
    0xc3                                            // ret                 (1)
  };
  std::memcpy(code, body, sizeof(body));

  fh::DetourHandle h;
  if (!fh::install_detour(reinterpret_cast<void*>(code),
                          reinterpret_cast<void*>(&hook_impl), h)) {
    std::fprintf(stderr, "install_detour failed\n");
    return 1;
  }
  g_tramp = reinterpret_cast<VoidFn>(h.trampoline);

  auto fn = reinterpret_cast<VoidFn>(code);
  int r = fn();
  std::fprintf(stderr, "[plain prologue] returned %d, hook=%d orig=%d\n",
               r, g_hook_called, g_orig_called);
  if (r != 142 || g_hook_called != 1) {
    std::fprintf(stderr, "  FAIL (expected return=142 hook=1, got return=%d hook=%d)\n",
                 r, g_hook_called);
    return 1;
  }
  fh::uninstall_detour(h);
  int r2 = fn();
  std::fprintf(stderr, "[plain prologue] post-uninstall returned %d, hook=%d\n",
               r2, g_hook_called);
  if (r2 != 42 || g_hook_called != 1) {
    std::fprintf(stderr, "  FAIL (uninstall)\n");
    return 1;
  }
  std::fprintf(stderr, "[plain prologue] OK\n");
  return 0;
}

// Test 2: a RIP-relative LEA prologue. Demonstrates Zydis rewrites disp32.
std::int64_t g_data_target = 0xabcd1234;
std::int64_t g_loaded_value = 0;
VoidFn g_rip_tramp = nullptr;

// We'll place a function that does: lea rax, [rip+offset]; mov rax, [rax]; ret.
// Then we'll install a detour and verify the trampoline's lea still points
// at g_data_target.
int rip_hook_impl() {
  // Call original via trampoline
  int r = g_rip_tramp();
  return r + 1;
}

int test_rip_relative_prologue() {
  // Two adjacent pages: code (will become RX after detour) + data (stays RW).
  // This matches the realistic case where code and the globals it reads live
  // in different pages.
  long ps = sysconf(_SC_PAGESIZE);
  std::uint8_t* block = static_cast<std::uint8_t*>(
      mmap(nullptr, 2 * ps, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (block == MAP_FAILED) return 1;
  std::uint8_t* code = block;
  std::uint8_t* data_page = block + ps;
  std::int64_t* data_src = reinterpret_cast<std::int64_t*>(data_page);
  std::int64_t* data_dst = reinterpret_cast<std::int64_t*>(data_page + 8);
  *data_src = 0xabcd1234;
  *data_dst = 0;
  std::uint8_t* p = code;
  // LEA rax, [rip+d32]     (7 bytes) — target = data_src
  *p++ = 0x48; *p++ = 0x8d; *p++ = 0x05;
  std::int32_t d32 = static_cast<std::int32_t>(
      reinterpret_cast<std::int64_t>(data_src)
      - reinterpret_cast<std::int64_t>(p + 4));
  std::memcpy(p, &d32, 4); p += 4;
  // MOV rax, [rax]         (3 bytes)
  *p++ = 0x48; *p++ = 0x8b; *p++ = 0x00;
  // MOV [rip+d32_2], rax   (7 bytes) — target = data_dst
  *p++ = 0x48; *p++ = 0x89; *p++ = 0x05;
  std::int32_t d32_2 = static_cast<std::int32_t>(
      reinterpret_cast<std::int64_t>(data_dst)
      - reinterpret_cast<std::int64_t>(p + 4));
  std::memcpy(p, &d32_2, 4); p += 4;
  // xor eax, eax; ret
  *p++ = 0x31; *p++ = 0xc0;
  *p++ = 0xc3;
  // Pad with nops
  while (p - code < 64) *p++ = 0x90;

  // Sanity check: run it once without detour.
  *data_dst = 0;
  auto fn = reinterpret_cast<VoidFn>(code);
  fn();
  std::fprintf(stderr, "[rip-rel] pre-detour: *data_dst=0x%lx (expect 0xabcd1234)\n",
               (unsigned long)*data_dst);
  if (*data_dst != 0xabcd1234) return 1;

  fh::DetourHandle h;
  if (!fh::install_detour(reinterpret_cast<void*>(code),
                          reinterpret_cast<void*>(&rip_hook_impl), h)) {
    std::fprintf(stderr, "install_detour (rip) failed\n");
    return 1;
  }
  g_rip_tramp = reinterpret_cast<VoidFn>(h.trampoline);

  *data_dst = 0;
  *data_src = 0x12345678;  // change source so we can detect trampoline reading through RIP-relative
  fn();  // goes through hook -> trampoline -> back into code
  std::fprintf(stderr, "[rip-rel] post-detour: *data_dst=0x%lx (expect 0x12345678)\n",
               (unsigned long)*data_dst);
  if (*data_dst != 0x12345678) {
    std::fprintf(stderr, "  FAIL: trampoline's RIP-relative LEA was not re-relocated\n");
    return 1;
  }
  fh::uninstall_detour(h);
  std::fprintf(stderr, "[rip-rel] OK\n");
  return 0;
}

}  // namespace

int main() {
  int rc = 0;
  rc |= test_plain_prologue();
  rc |= test_rip_relative_prologue();
  std::fprintf(stderr, "%s\n", rc ? "FAIL" : "ALL TESTS PASS");
  return rc;
}
