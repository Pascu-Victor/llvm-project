//===-- sanitizer_stoptheworld_wos.h ----------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef SANITIZER_STOPTHEWORLD_WOS_H
#define SANITIZER_STOPTHEWORLD_WOS_H

#include "sanitizer_stoptheworld.h"

namespace __sanitizer {

class SuspendedThreadsListWOS final : public SuspendedThreadsList {};

}  // namespace __sanitizer

#endif  // SANITIZER_STOPTHEWORLD_WOS_H
