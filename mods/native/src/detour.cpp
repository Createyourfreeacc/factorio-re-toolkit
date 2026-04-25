// x86-64 detour engine with Zydis-backed prologue relocation.
//
// Strategy:
//   1. Decode instructions at the target with Zydis until we have at least
//      14 bytes. These "displaced" instructions will be copied into a
//      trampoline that also jumps back into (target + displaced_size).
//   2. While copying, re-encode operands that are RIP-relative, and branches
//      whose targets moved out of relative reach:
//        * memory operands with base=RIP, disp32 → new disp32 = old disp + (old_rip - new_rip)
//        * near CALL rel32 / JMP rel32 / Jcc rel32 / LOOP / JCXZ → recompute or abort
//        * short JMP rel8 / Jcc rel8 → promote to rel32
//   3. Overwrite the target prologue with a 14-byte absolute jump
//      (movabs rax, hook; jmp rax).
//
// Fail-safe: if we encounter an instruction we can't safely relocate
// (indirect branch control flow unrelated to RIP-relative data, or an
// unhandled edge case), we log and refuse to install the detour rather
// than corrupt the trampoline.

#include "detour.hpp"
#include "log.hpp"

#include <Zydis/Zydis.h>
#include <cstdint>
#include <cstring>
#include <sys/mman.h>
#include <unistd.h>

namespace factorio_hooks {

namespace {

constexpr std::size_t kPatchSize = 14;
constexpr std::size_t kTrampolineReserve = 128;  // enough for displaced + promoted branches + abs jmp

void write_abs_jmp(std::uint8_t* dst, void* target) {
  // movabs rax, imm64 ; jmp rax  (14 bytes; no RIP-relative, no PIC issues)
  dst[0]  = 0x48; dst[1]  = 0xb8;
  std::memcpy(dst + 2, &target, sizeof(target));
  dst[10] = 0xff; dst[11] = 0xe0;
  dst[12] = 0xcc; dst[13] = 0xcc;
}

bool mprotect_span(void* addr, std::size_t len, int prot) {
  long pagesize = sysconf(_SC_PAGESIZE);
  auto a = reinterpret_cast<std::uintptr_t>(addr);
  auto page_start = a & ~static_cast<std::uintptr_t>(pagesize - 1);
  std::size_t span = (a + len) - page_start;
  // Round up to whole pages:
  span = ((span + pagesize - 1) / pagesize) * pagesize;
  return mprotect(reinterpret_cast<void*>(page_start), span, prot) == 0;
}

void* alloc_rwx_page(std::size_t bytes) {
  long pagesize = sysconf(_SC_PAGESIZE);
  std::size_t span = ((bytes + pagesize - 1) / pagesize) * pagesize;
  void* p = mmap(nullptr, span, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return (p == MAP_FAILED) ? nullptr : p;
}

// Append instruction `insn` (length `n`) into the trampoline at offset `t_off`,
// rewriting RIP-relative operands and rel-branches for the new location.
// `orig_ip` is the address of the original instruction; `new_ip` is where we
// are writing it in the trampoline. Returns bytes written to trampoline, or 0
// on failure.
std::size_t relocate_one(const ZydisDisassembledInstruction& dis,
                         const std::uint8_t* src_bytes,
                         std::uintptr_t orig_ip,
                         std::uint8_t* tramp,
                         std::uintptr_t new_ip) {
  const auto& info = dis.info;
  std::size_t n = info.length;
  std::memcpy(tramp, src_bytes, n);

  // Handle relative branch instructions by promoting rel8 to rel32 or
  // recomputing rel32.
  //   * Unconditional near JMP (opcode E9 rel32) or short JMP (EB rel8)
  //   * Conditional near/short Jcc
  //   * CALL near rel32 (E8)
  //   * LOOP/LOOPE/LOOPNE (E0/E1/E2) and JCXZ/JRCXZ/JECXZ (E3)
  const ZydisMnemonic m = info.mnemonic;
  bool is_rel_branch = false;
  bool is_call = (m == ZYDIS_MNEMONIC_CALL);
  bool is_jmp = (m == ZYDIS_MNEMONIC_JMP);
  bool is_jcc = (m >= ZYDIS_MNEMONIC_JB && m <= ZYDIS_MNEMONIC_JS);
  bool is_loop = (m == ZYDIS_MNEMONIC_LOOP || m == ZYDIS_MNEMONIC_LOOPE
                  || m == ZYDIS_MNEMONIC_LOOPNE
                  || m == ZYDIS_MNEMONIC_JCXZ
                  || m == ZYDIS_MNEMONIC_JKZD
                  || m == ZYDIS_MNEMONIC_JRCXZ);

  // Check if any operand is a relative immediate
  for (int i = 0; i < info.operand_count_visible; ++i) {
    const auto& op = dis.operands[i];
    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && op.imm.is_relative) {
      is_rel_branch = true;
      break;
    }
  }

  if (is_rel_branch) {
    // Compute absolute branch target from Zydis
    ZyanU64 abs_target = 0;
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(&info, &dis.operands[0], orig_ip, &abs_target))) {
      FH_LOG("detour: failed to resolve relative branch target in prologue");
      return 0;
    }

    if (is_loop) {
      // LOOP / JCXZ have only 8-bit displacement and no 32-bit form. If the
      // target is still in reach of `new_ip`, keep; else bail.
      std::int64_t delta = static_cast<std::int64_t>(abs_target)
                         - static_cast<std::int64_t>(new_ip + n);
      if (delta < INT8_MIN || delta > INT8_MAX) {
        FH_LOG("detour: LOOP/JCXZ in prologue, target out of rel8 reach — bail");
        return 0;
      }
      tramp[n - 1] = static_cast<std::uint8_t>(delta);
      return n;
    }

    if (is_jmp || is_call || is_jcc) {
      // Always re-emit as near form (rel32). For short forms we need to
      // rewrite the encoding.
      std::int64_t target_off = static_cast<std::int64_t>(abs_target)
                              - static_cast<std::int64_t>(new_ip);
      // Near form length = 5 for JMP/CALL, 6 for Jcc (0f xx rel32).
      // We'll write the worst-case promoted form.
      if (is_jmp) {
        // E9 rel32
        std::int64_t rel = target_off - 5;
        if (rel < INT32_MIN || rel > INT32_MAX) {
          FH_LOG("detour: JMP target out of rel32 reach from trampoline");
          return 0;
        }
        tramp[0] = 0xe9;
        std::int32_t r = static_cast<std::int32_t>(rel);
        std::memcpy(tramp + 1, &r, 4);
        return 5;
      }
      if (is_call) {
        std::int64_t rel = target_off - 5;
        if (rel < INT32_MIN || rel > INT32_MAX) {
          FH_LOG("detour: CALL target out of rel32 reach from trampoline");
          return 0;
        }
        tramp[0] = 0xe8;
        std::int32_t r = static_cast<std::int32_t>(rel);
        std::memcpy(tramp + 1, &r, 4);
        return 5;
      }
      // Jcc: need the 0F-prefixed near form. Zydis mnemonic -> near opcode.
      std::uint8_t cc = 0;
      switch (m) {
        case ZYDIS_MNEMONIC_JO:  cc = 0x80; break;
        case ZYDIS_MNEMONIC_JNO: cc = 0x81; break;
        case ZYDIS_MNEMONIC_JB:  cc = 0x82; break;
        case ZYDIS_MNEMONIC_JNB: cc = 0x83; break;
        case ZYDIS_MNEMONIC_JZ:  cc = 0x84; break;
        case ZYDIS_MNEMONIC_JNZ: cc = 0x85; break;
        case ZYDIS_MNEMONIC_JBE: cc = 0x86; break;
        case ZYDIS_MNEMONIC_JNBE:cc = 0x87; break;
        case ZYDIS_MNEMONIC_JS:  cc = 0x88; break;
        case ZYDIS_MNEMONIC_JNS: cc = 0x89; break;
        case ZYDIS_MNEMONIC_JP:  cc = 0x8a; break;
        case ZYDIS_MNEMONIC_JNP: cc = 0x8b; break;
        case ZYDIS_MNEMONIC_JL:  cc = 0x8c; break;
        case ZYDIS_MNEMONIC_JNL: cc = 0x8d; break;
        case ZYDIS_MNEMONIC_JLE: cc = 0x8e; break;
        case ZYDIS_MNEMONIC_JNLE:cc = 0x8f; break;
        default:
          FH_LOG("detour: unsupported Jcc mnemonic %u in prologue",
                 static_cast<unsigned>(m));
          return 0;
      }
      std::int64_t rel = target_off - 6;
      if (rel < INT32_MIN || rel > INT32_MAX) {
        FH_LOG("detour: Jcc target out of rel32 reach from trampoline");
        return 0;
      }
      tramp[0] = 0x0f;
      tramp[1] = cc;
      std::int32_t r = static_cast<std::int32_t>(rel);
      std::memcpy(tramp + 2, &r, 4);
      return 6;
    }
  }

  // Handle memory operand with RIP-relative addressing (e.g. "lea rax,[rip+X]"
  // or "mov rax,[rip+X]"). We patch the disp32 in the instruction bytes.
  for (int i = 0; i < info.operand_count_visible; ++i) {
    const auto& op = dis.operands[i];
    if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
    if (op.mem.base != ZYDIS_REGISTER_RIP) continue;

    if (info.raw.disp.size != 32) {
      FH_LOG("detour: RIP-relative with non-32-bit disp (size=%u) not handled",
             info.raw.disp.size);
      return 0;
    }
    // Offset of the disp32 field inside the instruction
    std::size_t disp_off = info.raw.disp.offset;
    std::int32_t old_disp;
    std::memcpy(&old_disp, tramp + disp_off, 4);
    // Original effective address = orig_ip + instruction_length + old_disp.
    // We want new_disp such that new_ip + instruction_length + new_disp
    // == original effective address.
    std::int64_t effective = static_cast<std::int64_t>(orig_ip) + n + old_disp;
    std::int64_t new_disp_64 = effective - static_cast<std::int64_t>(new_ip) - n;
    if (new_disp_64 < INT32_MIN || new_disp_64 > INT32_MAX) {
      FH_LOG("detour: RIP-relative disp out of rel32 reach after relocation");
      return 0;
    }
    std::int32_t new_disp = static_cast<std::int32_t>(new_disp_64);
    std::memcpy(tramp + disp_off, &new_disp, 4);
    FH_LOG("detour: RIP-rel reloc: orig_ip=0x%lx n=%zu old_disp=%d "
           "effective=0x%lx new_ip=0x%lx new_disp=%d",
           (unsigned long)orig_ip, n, old_disp,
           (unsigned long)effective, (unsigned long)new_ip, new_disp);
    break;
  }

  return n;
}

// Decode prologue and relocate into `tramp`. Fills `out_displaced` with the
// count of source bytes displaced from the target, and returns count of
// bytes written to the trampoline (before the final jump-back).
// Returns 0 on failure.
std::size_t build_trampoline(const std::uint8_t* target,
                             std::uint8_t* tramp,
                             std::uintptr_t target_addr,
                             std::uintptr_t tramp_addr,
                             std::size_t& out_displaced) {
  ZydisDisassembledInstruction dis;
  std::size_t src_off = 0;
  std::size_t dst_off = 0;
  // Cap: decode until we cover >= kPatchSize source bytes or hit a return/uncondjmp.
  while (src_off < kPatchSize) {
    if (dst_off + ZYDIS_MAX_INSTRUCTION_LENGTH + 8 > kTrampolineReserve) {
      FH_LOG("detour: trampoline reserve too small");
      return 0;
    }
    if (ZYAN_FAILED(ZydisDisassembleIntel(
            ZYDIS_MACHINE_MODE_LONG_64,
            target_addr + src_off,
            target + src_off,
            ZYDIS_MAX_INSTRUCTION_LENGTH,
            &dis))) {
      FH_LOG("detour: failed to decode instruction at +%zu", src_off);
      return 0;
    }
    std::size_t n_src = dis.info.length;
    std::size_t n_dst = relocate_one(dis, target + src_off,
                                     target_addr + src_off,
                                     tramp + dst_off,
                                     tramp_addr + dst_off);
    if (n_dst == 0) return 0;  // abort
    // If the decoded instruction is a final control-flow transfer (ret or
    // unconditional jmp outside the function), we still relocate it and
    // stop early; but we still must cover kPatchSize source bytes, so treat
    // it as a failure.
    src_off += n_src;
    dst_off += n_dst;
    if (dis.info.mnemonic == ZYDIS_MNEMONIC_RET
        || dis.info.mnemonic == ZYDIS_MNEMONIC_INT3) {
      if (src_off < kPatchSize) {
        FH_LOG("detour: function ends before %zu bytes (length %zu). "
               "Don't hook such small stubs.", kPatchSize, src_off);
        return 0;
      }
    }
  }
  out_displaced = src_off;
  return dst_off;
}

}  // namespace

bool install_detour(void* target, void* hook, DetourHandle& out) {
  if (!target || !hook) return false;

  out.target = target;
  // Save up to kPatchSize original bytes for uninstall
  std::memcpy(out.original_bytes, target, kPatchSize);
  out.patch_size = kPatchSize;

  // Allocate trampoline
  void* tramp = alloc_rwx_page(kTrampolineReserve);
  if (!tramp) {
    FH_LOG("detour: trampoline mmap failed");
    return false;
  }
  auto* tb = static_cast<std::uint8_t*>(tramp);

  std::size_t displaced = 0;
  std::size_t dst_len = build_trampoline(
      static_cast<const std::uint8_t*>(target),
      tb,
      reinterpret_cast<std::uintptr_t>(target),
      reinterpret_cast<std::uintptr_t>(tb),
      displaced);
  if (dst_len == 0) {
    munmap(tramp, kTrampolineReserve);
    return false;
  }

  // Append absolute jump back to (target + displaced)
  void* resume = static_cast<std::uint8_t*>(target) + displaced;
  if (dst_len + 14 > kTrampolineReserve) {
    FH_LOG("detour: trampoline reserve too small for final jmp");
    munmap(tramp, kTrampolineReserve);
    return false;
  }
  write_abs_jmp(tb + dst_len, resume);

  if (mprotect(tramp, kTrampolineReserve, PROT_READ | PROT_EXEC) != 0) {
    FH_LOG("detour: mprotect(trampoline) failed");
    munmap(tramp, kTrampolineReserve);
    return false;
  }
  out.trampoline = tramp;

  // Install the patch at the target
  if (!mprotect_span(target, kPatchSize, PROT_READ | PROT_WRITE | PROT_EXEC)) {
    FH_LOG("detour: mprotect(target W) failed at %p", target);
    return false;
  }
  std::uint8_t patch[kPatchSize];
  write_abs_jmp(patch, hook);
  std::memcpy(target, patch, kPatchSize);
  __builtin___clear_cache(static_cast<char*>(target),
                          static_cast<char*>(target) + kPatchSize);
  if (!mprotect_span(target, kPatchSize, PROT_READ | PROT_EXEC)) {
    FH_LOG("detour: mprotect(target RX) failed at %p", target);
    return false;
  }

  FH_LOG("detour: %p -> %p (trampoline %p, displaced %zu src / %zu dst bytes)",
         target, hook, tramp, displaced, dst_len);
  return true;
}

bool uninstall_detour(const DetourHandle& h) {
  if (!h.target) return false;
  if (!mprotect_span(h.target, h.patch_size, PROT_READ | PROT_WRITE | PROT_EXEC)) return false;
  std::memcpy(h.target, h.original_bytes, h.patch_size);
  __builtin___clear_cache(static_cast<char*>(h.target),
                          static_cast<char*>(h.target) + h.patch_size);
  return mprotect_span(h.target, h.patch_size, PROT_READ | PROT_EXEC);
}

}  // namespace factorio_hooks
