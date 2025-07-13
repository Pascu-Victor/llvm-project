//===-- sanitizer_stoptheworld_wos.cpp -----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===---------------------------------------------------------------------===//
//
// See sanitizer_stoptheworld.h for details.
//
//===---------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_WOS

#  include "sanitizer_stoptheworld.h"
#  include "sanitizer_stoptheworld_wos.h"

namespace __sanitizer {

// The Fuchsia implementation stops the world but doesn't offer a real
// SuspendedThreadsList argument.  This is enough for ASan's use case,
// and LSan does not use this API on Fuchsia.
void StopTheWorld(StopTheWorldCallback callback, void *argument) {
  //   struct Params {
  //     StopTheWorldCallback callback;
  //     void *argument;
  //   } params = {callback, argument};
  //   __sanitizer_memory_snapshot(
  //       nullptr, nullptr, nullptr, nullptr,
  //       [](u64, void *data) {
  //         auto params = reinterpret_cast<Params *>(data);
  //         params->callback(SuspendedThreadsListWOS(), params->argument);
  //       },
  //       &params);
  while (true) {
    // FIXME: This is a stub implementation.
  }
}

}  // namespace __sanitizer

#endif  // SANITIZER_WOS
