//===-- sanitizer_syscall_wos_x86_64.inc ----------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Implementations of internal_syscall and internal_iserror for WOS/x86_64.
//
//===----------------------------------------------------------------------===//

#include <sys/callnums.h>

// Syscall number in rax, args in rdi, rsi, rdx, rcx, r8, r9.
// Return value in rax. rcx and r11 are clobbered.

static uptr internal_syscall(ker::abi::callnums nr) {
    u64 retval;
    // Syscall number in rax.
    asm volatile("syscall"
                             : "=a"(retval) // output: retval in rax
                             : "a"((u64)nr)      // input: nr in rax
                             : "rcx", "r11", "memory", "cc"); // clobbers
    return retval;
}

template <typename T1>
static uptr internal_syscall(ker::abi::callnums nr, T1 arg1) {
    u64 retval;
    // nr in rax, arg1 in rdi.
    asm volatile("syscall"
                             : "=a"(retval) // output: retval in rax
                             : "a"((u64)nr), "D"((u64)arg1) // inputs: nr in rax, arg1 in rdi
                             : "rcx", "r11", "memory", "cc"); // clobbers
    return retval;
}

template <typename T1, typename T2>
static uptr internal_syscall(ker::abi::callnums nr, T1 arg1, T2 arg2) {
    u64 retval;
    // nr in rax, arg1 in rdi, arg2 in rsi.
    asm volatile("syscall"
                             : "=a"(retval) // output: retval in rax
                             : "a"((u64)nr), "D"((u64)arg1), "S"((u64)arg2) // inputs: nr, arg1, arg2
                             : "rcx", "r11", "memory", "cc"); // clobbers
    return retval;
}

template <typename T1, typename T2, typename T3>
static uptr internal_syscall(ker::abi::callnums nr, T1 arg1, T2 arg2, T3 arg3) {
    u64 retval;
    // nr in rax, arg1 in rdi, arg2 in rsi, arg3 in rdx.
    asm volatile("syscall"
                             : "=a"(retval) // output: retval in rax
                             : "a"((u64)nr), "D"((u64)arg1), "S"((u64)arg2), "d"((u64)arg3) // inputs
                             : "rcx", "r11", "memory", "cc"); // clobbers
    return retval;
}

template <typename T1, typename T2, typename T3, typename T4>
static uptr internal_syscall(ker::abi::callnums nr, T1 arg1, T2 arg2, T3 arg3, T4 arg4) {
    u64 retval;
    // nr in rax, arg1 in rdi, arg2 in rsi, arg3 in rdx, arg4 in rcx.
    asm volatile("syscall"
                             : "=a"(retval) // output: retval in rax
                             : "a"((u64)nr), "D"((u64)arg1), "S"((u64)arg2), "d"((u64)arg3), "c"((u64)arg4) // inputs
                             : "r11", "memory", "cc"); // clobbers: rcx (implicit), r11
    return retval;
}

template <typename T1, typename T2, typename T3, typename T4, typename T5>
static uptr internal_syscall(ker::abi::callnums nr, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5) {
    u64 retval;
    // nr in rax, arg1 in rdi, arg2 in rsi, arg3 in rdx, arg4 in rcx, arg5 in r8.
    // Use "r" for arg5 and explicitly move it to %r8.
    asm volatile("mov %6, %%r8;" // Move arg5 (%6) to r8
                             "syscall"
                             : "=a"(retval) // output: retval in rax
                             : "a"((u64)nr), "D"((u64)arg1), "S"((u64)arg2), "d"((u64)arg3), "c"((u64)arg4), "r"((u64)arg5) // inputs
                             : "r8", "r11", "memory", "cc"); // clobbers: rcx (implicit), r8, r11
    return retval;
}

template <typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
static uptr internal_syscall(ker::abi::callnums nr, T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6) {
    u64 retval;
    // nr in rax, arg1 in rdi, arg2 in rsi, arg3 in rdx, arg4 in rcx, arg5 in r8, arg6 in r9.
    // Use "r" for arg5/arg6 and explicitly move them.
    asm volatile("mov %6, %%r8;"  // Move arg5 (%6) to r8
                             "mov %7, %%r9;"  // Move arg6 (%7) to r9
                             "syscall"
                             : "=a"(retval) // output: retval in rax
                             : "a"((u64)nr), "D"((u64)arg1), "S"((u64)arg2), "d"((u64)arg3), "c"((u64)arg4), "r"((u64)arg5), "r"((u64)arg6) // inputs
                             : "r8", "r9", "r11", "memory", "cc"); // clobbers: rcx (implicit), r8, r9, r11
    return retval;
}

bool internal_iserror(uptr retval, int *rverrno) {
    // WOS uses the standard Linux error convention: -4095..-1 indicates error.
    if (retval >= (uptr)-4095) {
        if (rverrno)
            *rverrno = -retval;
        return true;
    }
    return false;
}
