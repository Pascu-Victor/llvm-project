//===-- sanitizer_wos.h ---------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// WOS-specific syscall wrappers and classes.
//
//===----------------------------------------------------------------------===//
#ifndef SANITIZER_WOS_H
#define SANITIZER_WOS_H

#include "sanitizer_platform.h"
#if SANITIZER_WOS
#  include "sanitizer_common.h"
#  include "sanitizer_internal_defs.h"
#  include "sanitizer_platform_limits_wos.h"
#  include "sanitizer_posix.h"

struct link_map;  // Opaque type returned by dlopen().
struct utsname;

namespace __sanitizer {
// Dirent structure for getdents(). Note that this structure is different from
// the one in <dirent.h>, which is used by readdir().
struct wos_dirent;

struct ProcSelfMapsBuff {
  char *data;
  uptr mmaped_size;
  uptr len;
};

struct MemoryMappingLayoutData {
  ProcSelfMapsBuff proc_self_maps;
  const char *current;
};

void ReadProcMaps(ProcSelfMapsBuff *proc_maps);

// Syscall wrappers.
uptr internal_getdents(fd_t fd, struct wos_dirent *dirp, unsigned int count);
uptr internal_sigaltstack(const void *ss, void *oss);
uptr internal_sigprocmask(int how, __sanitizer_sigset_t *set,
                          __sanitizer_sigset_t *oldset);

void SetSigProcMask(__sanitizer_sigset_t *set, __sanitizer_sigset_t *oldset);
void BlockSignals(__sanitizer_sigset_t *oldset = nullptr);
struct ScopedBlockSignals {
  explicit ScopedBlockSignals(__sanitizer_sigset_t *copy);
  ~ScopedBlockSignals();

  ScopedBlockSignals &operator=(const ScopedBlockSignals &) = delete;
  ScopedBlockSignals(const ScopedBlockSignals &) = delete;

 private:
  __sanitizer_sigset_t saved_;
};

#  if SANITIZER_GLIBC
uptr internal_clock_gettime(__sanitizer_clockid_t clk_id, void *tp);
#  endif

uptr internal_prctl(int option, uptr arg2, uptr arg3, uptr arg4, uptr arg5);
uptr internal_arch_prctl(int option, uptr arg2);
// Used only by sanitizer_stoptheworld. Signal handlers that are actually used
// (like the process-wide error reporting SEGV handler) must use
// internal_sigaction instead.
int internal_sigaction_norestorer(int signum, const void *act, void *oldact);
void internal_sigdelset(__sanitizer_sigset_t *set, int signum);
uptr internal_clone(int (*fn)(void *), void *child_stack, int flags, void *arg,
                    int *parent_tidptr, void *newtls, int *child_tidptr);
int internal_uname(struct utsname *buf);

// This class reads thread IDs from /proc/<pid>/task using only syscalls.
class ThreadLister {
 public:
  explicit ThreadLister(pid_t pid);
  enum Result {
    Error,
    Incomplete,
    Ok,
  };
  Result ListThreads(InternalMmapVector<ThreadID> *threads);
  const char *LoadStatus(ThreadID tid);

 private:
  bool IsAlive(ThreadID tid);

  InternalScopedString task_path_;
  InternalScopedString status_path_;
  InternalMmapVector<char> buffer_;
};

// Exposed for testing.
uptr ThreadDescriptorSize();
uptr ThreadSelf();

// Matches a library's file name against a base name (stripping path and version
// information).
bool LibraryNameIs(const char *full_name, const char *base_name);

// Call cb for each region mapped by map.
void ForEachMappedRegion(link_map *map, void (*cb)(const void *, uptr));

// Releases memory pages entirely within the [beg, end] address range.
// The pages no longer count toward RSS; reads are guaranteed to return 0.
// Requires (but does not verify!) that pages are MAP_PRIVATE.
inline void ReleaseMemoryPagesToOSAndZeroFill(uptr beg, uptr end) {
  // man madvise on Linux promises zero-fill for anonymous private pages.
  // Testing shows the same behaviour for private (but not anonymous) mappings
  // of shm_open() files, as long as the underlying file is untouched.
  CHECK(SANITIZER_WOS);
  ReleaseMemoryPagesToOS(beg, end);
}

}  // namespace __sanitizer

#endif
#endif  // SANITIZER_WOS_H
