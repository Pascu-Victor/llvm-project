//===-- fuchsia.h -----------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef SCUDO_WOS_H_
#define SCUDO_WOS_H_

#include "platform.h"

#if SCUDO_WOS

#include <stdint.h>

namespace scudo {

struct MapPlatformData {};

} // namespace scudo

#endif // SCUDO_WOS

#endif // SCUDO_WOS_H_
