//===-- mem_map_wos.cpp ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "platform.h"

#if SCUDO_WOS

#include "mem_map_wos.h"

#include "common.h"
#include "internal_defs.h"
#include "mutex.h"
#include "report_wos.h"
#include "string_utils.h"
#include "wos.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <wos/futex.h>

namespace scudo {

static void *mmapWrapper(uptr Addr, uptr Size, const char *Name, uptr Flags) {
  int MmapFlags = MAP_PRIVATE | MAP_ANONYMOUS;
  int MmapProt;
  if (Flags & MAP_NOACCESS) {
    MmapFlags |= MAP_NORESERVE;
    MmapProt = PROT_NONE;
  } else {
    MmapProt = PROT_READ | PROT_WRITE;
  }
  if (Addr)
    MmapFlags |= MAP_FIXED;
  void *P =
      mmap(reinterpret_cast<void *>(Addr), Size, MmapProt, MmapFlags, -1, 0);
  if (P == MAP_FAILED) {
    if (!(Flags & MAP_ALLOWNOMEM) || errno != ENOMEM)
      reportMapError(errno == ENOMEM ? Size : 0);
    return nullptr;
  }
  (void)Name;
  return P;
}

bool MemMapWOS::mapImpl(uptr Addr, uptr Size, const char *Name, uptr Flags) {
  void *P = mmapWrapper(Addr, Size, Name, Flags);
  if (P == nullptr)
    return false;

  MapBase = reinterpret_cast<uptr>(P);
  MapCapacity = Size;
  return true;
}

void MemMapWOS::unmapImpl(uptr Addr, uptr Size) {
  // If we unmap all the pages, also mark `MapBase` to 0 to indicate invalid
  // status.
  if (Size == MapCapacity) {
    MapBase = MapCapacity = 0;
  } else {
    // This is partial unmap and is unmapping the pages from the beginning,
    // shift `MapBase` to the new base.
    if (MapBase == Addr)
      MapBase = Addr + Size;
    MapCapacity -= Size;
  }

  if (munmap(reinterpret_cast<void *>(Addr), Size) != 0)
    reportUnmapError(Addr, Size);
}

bool MemMapWOS::remapImpl(uptr Addr, uptr Size, const char *Name, uptr Flags) {
  void *P = mmapWrapper(Addr, Size, Name, Flags);
  if (reinterpret_cast<uptr>(P) != Addr)
    reportMapError();
  return true;
}

void MemMapWOS::setMemoryPermissionImpl(uptr Addr, uptr Size, uptr Flags) {
  int Prot = (Flags & MAP_NOACCESS) ? PROT_NONE : (PROT_READ | PROT_WRITE);
  if (mprotect(reinterpret_cast<void *>(Addr), Size, Prot) != 0)
    reportProtectError(Addr, Size, Prot);
}

void MemMapWOS::releaseAndZeroPagesToOSImpl(uptr From, uptr Size) {
  void *Addr = reinterpret_cast<void *>(From);

  while (madvise(Addr, Size, MADV_DONTNEED) == -1 && errno == EAGAIN) {
  }
}

bool ReservedMemoryWOS::createImpl(uptr Addr, uptr Size, const char *Name,
                                   uptr Flags) {
  ReservedMemoryWOS::MemMapT MemMap;
  if (!MemMap.map(Addr, Size, Name, Flags | MAP_NOACCESS))
    return false;

  MapBase = MemMap.getBase();
  MapCapacity = MemMap.getCapacity();

  return true;
}

void ReservedMemoryWOS::releaseImpl() {
  if (munmap(reinterpret_cast<void *>(getBase()), getCapacity()) != 0)
    reportUnmapError(getBase(), getCapacity());
}

ReservedMemoryWOS::MemMapT ReservedMemoryWOS::dispatchImpl(uptr Addr,
                                                           uptr Size) {
  return ReservedMemoryWOS::MemMapT(Addr, Size);
}

} // namespace scudo

#endif // SCUDO_WOS
