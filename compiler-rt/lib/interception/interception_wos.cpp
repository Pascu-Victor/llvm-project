//===-- interception_wos.cpp ----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressSanitizer, an address sanity checker.
//
// WOS-specific interception methods.
//===----------------------------------------------------------------------===//

#include "interception.h"

#if SANITIZER_WOS

#  include <dlfcn.h>  // for dlsym() and dlvsym()

namespace __interception {

static void *GetFuncAddr(const char *name, uptr trampoline) {
  void *addr = dlsym(RTLD_NEXT, name);
  if (!addr) {
    // If the lookup using RTLD_NEXT failed, the sanitizer runtime library is
    // later in the library search order than the DSO that we are trying to
    // intercept, which means that we cannot intercept this function. We still
    // want the address of the real definition, though, so look it up using
    // RTLD_DEFAULT.
    addr = dlsym(RTLD_DEFAULT, name);

    // In case `name' is not loaded, dlsym ends up finding the actual wrapper.
    // We don't want to intercept the wrapper and have it point to itself.
    if ((uptr)addr == trampoline)
      addr = nullptr;
  }
  return addr;
}

bool InterceptFunction(const char *name, uptr *ptr_to_real, uptr func,
                       uptr trampoline) {
  void *addr = GetFuncAddr(name, trampoline);
  *ptr_to_real = (uptr)addr;
  return addr && (func == trampoline);
}

}  // namespace __interception

#endif  // SANITIZER_WOS
