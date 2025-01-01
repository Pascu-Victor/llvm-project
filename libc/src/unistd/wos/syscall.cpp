//===-- WOS implementation of syscall -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "src/unistd/syscall.h"

#include "src/__support/OSUtil/syscall.h" // For internal syscall function.
#include "src/__support/common.h"

#include "src/__support/macros/config.h"
#include "src/errno/libc_errno.h"
#include <stdarg.h>

namespace LIBC_NAMESPACE_DECL {

LLVM_LIBC_FUNCTION(long, __llvm_libc_syscall,
                   (uint64_t number, uint64_t arg1, uint64_t arg2,
                    uint64_t arg3, uint64_t arg4, uint64_t arg5,
                    uint64_t arg6)) {
  uint64_t ret = LIBC_NAMESPACE::syscall_impl<uint64_t>(number, arg1, arg2,
                                                        arg3, arg4, arg5, arg6);
  return ret;
}

} // namespace LIBC_NAMESPACE_DECL
