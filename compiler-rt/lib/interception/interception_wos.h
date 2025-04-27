//===-- interception_wos.h ------------------------------------*- C++ -*-===//
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

#if SANITIZER_WOS

#  if !defined(INCLUDED_FROM_INTERCEPTION_LIB)
#    error interception_wos.h should be included from interception library only
#  endif

#  ifndef INTERCEPTION_WOS_H
#    define INTERCEPTION_WOS_H

namespace __interception {
bool InterceptFunction(const char *name, uptr *ptr_to_real, uptr func,
                       uptr trampoline);
bool InterceptFunction(const char *name, const char *ver, uptr *ptr_to_real,
                       uptr func, uptr trampoline);
}  // namespace __interception

// Cast func to type of REAL(func) before casting to uptr in case it is an
// overloaded function, which is the case for some glibc functions when
// _FORTIFY_SOURCE is used. This disambiguates which overload to use.
#    define INTERCEPT_FUNCTION_WOS(func)                         \
      ::__interception::InterceptFunction(                       \
          #func, (::__interception::uptr *)&REAL(func),          \
          (::__interception::uptr)(decltype(REAL(func)))&(func), \
          (::__interception::uptr) & TRAMPOLINE(func))

#    define INTERCEPT_FUNCTION_VER_WOS(func, symver) \
      INTERCEPT_FUNCTION_WOS(func)

#  endif  // INTERCEPTION_WOS_H
#endif    // SANITIZER_WOS
