//===-- sanitizer_wos.cpp -----------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is shared between AddressSanitizer and ThreadSanitizer
// run-time libraries and implements WOS-specific functions from
// sanitizer_libc.h.
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_WOS
#  include <dlfcn.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <link.h>
#  include <pthread.h>
#  include <sched.h>
#  include <signal.h>
#  include <sys/hcf.h>
#  include <sys/mman.h>
#  include <sys/param.h>
#  include <sys/personality.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <sys/syscall.h>
#  include <sys/time.h>
#  include <sys/types.h>
#  include <sys/utsname.h>
#  include <ucontext.h>
#  include <unistd.h>

#  include "sanitizer_common.h"
#  include "sanitizer_flags.h"
#  include "sanitizer_getauxval.h"
#  include "sanitizer_internal_defs.h"
#  include "sanitizer_libc.h"
#  include "sanitizer_mutex.h"
#  include "sanitizer_placement_new.h"
#  include "sanitizer_procmaps.h"
#  include "sanitizer_wos.h"

extern char **environ;

struct kernel_timeval {
  long tv_sec;
  long tv_usec;
};

const int FUTEX_WAIT = 0;
const int FUTEX_WAKE = 1;
const int FUTEX_PRIVATE_FLAG = 128;
const int FUTEX_WAIT_PRIVATE = FUTEX_WAIT | FUTEX_PRIVATE_FLAG;
const int FUTEX_WAKE_PRIVATE = FUTEX_WAKE | FUTEX_PRIVATE_FLAG;

#  if !defined(GRND_NONBLOCK)
#    define GRND_NONBLOCK 1
#  endif
#  define SANITIZER_USE_GETRANDOM 1

namespace __sanitizer {

void SetSigProcMask(__sanitizer_sigset_t *set, __sanitizer_sigset_t *oldset) {
  CHECK_EQ(0, internal_sigprocmask(SIG_SETMASK, set, oldset));
}

// Assume SANITIZER_LINUX
// Deletes the specified signal from newset, if it is not present in oldset
// Equivalently: newset[signum] = newset[signum] & oldset[signum]
static void KeepUnblocked(__sanitizer_sigset_t &newset,
                          __sanitizer_sigset_t &oldset, int signum) {
  // FIXME: https://github.com/google/sanitizers/issues/1816
  // Assume !SANITIZER_ANDROID
  if (!internal_sigismember(&oldset, signum))
    internal_sigdelset(&newset, signum);
}

// Block asynchronous signals
void BlockSignals(__sanitizer_sigset_t *oldset) {
  __sanitizer_sigset_t newset;
  internal_sigfillset(&newset);
  __sanitizer_sigset_t currentset;

  // FIXME: https://github.com/google/sanitizers/issues/1816
  SetSigProcMask(NULL, &currentset);

  // Glibc uses SIGSETXID signal during setuid call. If this signal is blocked
  // on any thread, setuid call hangs.
  // See test/sanitizer_common/TestCases/Linux/setuid.c.
  KeepUnblocked(newset, currentset, 33);

  // Seccomp-BPF-sandboxed processes rely on SIGSYS to handle trapped syscalls.
  // If this signal is blocked, such calls cannot be handled and the process may
  // hang.
  KeepUnblocked(newset, currentset, 31);

  // Don't block synchronous signals
  // but also don't unblock signals that the user had deliberately blocked.
  // FIXME: https://github.com/google/sanitizers/issues/1816
  KeepUnblocked(newset, currentset, SIGSEGV);
  KeepUnblocked(newset, currentset, SIGBUS);
  KeepUnblocked(newset, currentset, SIGILL);
  KeepUnblocked(newset, currentset, SIGTRAP);
  KeepUnblocked(newset, currentset, SIGABRT);
  KeepUnblocked(newset, currentset, SIGFPE);
  KeepUnblocked(newset, currentset, SIGPIPE);

  SetSigProcMask(&newset, oldset);
}

ScopedBlockSignals::ScopedBlockSignals(__sanitizer_sigset_t *copy) {
  BlockSignals(&saved_);
  if (copy)
    internal_memcpy(copy, &saved_, sizeof(saved_));
}

ScopedBlockSignals::~ScopedBlockSignals() { SetSigProcMask(&saved_, nullptr); }

#  include "sanitizer_syscall_wos_x86_64.inc"

// --------------- sanitizer_libc.h
uptr internal_mmap(void *addr, uptr length, int prot, int flags, int fd,
                   u64 offset) {
#  pragma message "WARNING: internal_mmap is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(mmap), (uptr)addr, length, prot, flags,
  //   fd,
  //                          offset);
}

uptr internal_munmap(void *addr, uptr length) {
#  pragma message "WARNING: internal_munmap is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(munmap), (uptr)addr, length);
}

uptr internal_mremap(void *old_address, uptr old_size, uptr new_size, int flags,
                     void *new_address) {
#  pragma message "WARNING: internal_mremap is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(mremap), (uptr)old_address, old_size,
  //                          new_size, flags, (uptr)new_address);
}

int internal_mprotect(void *addr, uptr length, int prot) {
#  pragma message "WARNING: internal_mprotect is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(mprotect), (uptr)addr, length, prot);
}

int internal_madvise(uptr addr, uptr length, int advice) {
#  pragma message "WARNING: internal_madvise is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(madvise), addr, length, advice);
}

uptr internal_close(fd_t fd) {
#  pragma message "WARNING: internal_close is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(close), fd);
}

uptr internal_open(const char *filename, int flags) {
#  pragma message "WARNING: internal_open is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(openat), AT_FDCWD, (uptr)filename,
  //   flags);
}

uptr internal_open(const char *filename, int flags, u32 mode) {
#  pragma message "WARNING: internal_open is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(openat), AT_FDCWD, (uptr)filename, flags,
  //                          mode);
}

uptr internal_read(fd_t fd, void *buf, uptr count) {
#  pragma message "WARNING: internal_read is not implemented for WOS."
  hcf();
  //   sptr res;
  //   HANDLE_EINTR(res,
  //                (sptr)internal_syscall(SYSCALL(read), fd, (uptr)buf,
  //                count));
  //   return res;
}

uptr internal_write(fd_t fd, const void *buf, uptr count) {
#  pragma message "WARNING: internal_write is not implemented for WOS."
  hcf();
  //   sptr res;
  //   HANDLE_EINTR(res,
  //                (sptr)internal_syscall(SYSCALL(write), fd, (uptr)buf,
  //                count));
  //   return res;
}

uptr internal_ftruncate(fd_t fd, uptr size) {
#  pragma message "WARNING: internal_ftruncate is not implemented for WOS."
  hcf();
  //   sptr res;
  //   HANDLE_EINTR(res,
  //                (sptr)internal_syscall(SYSCALL(ftruncate), fd,
  //                (OFF_T)size));
  //   return res;
}

uptr internal_stat(const char *path, void *buf) {
#  pragma message "WARNING: internal_stat is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(newfstatat), AT_FDCWD, (uptr)path,
  //   (uptr)buf,
  //                          0);
}

uptr internal_lstat(const char *path, void *buf) {
#  pragma message "WARNING: internal_lstat is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(newfstatat), AT_FDCWD, (uptr)path,
  //   (uptr)buf,
  //                          AT_SYMLINK_NOFOLLOW);
}

uptr internal_fstat(fd_t fd, void *buf) {
#  pragma message "WARNING: internal_fstat is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(fstat), fd, (uptr)buf);
}

uptr internal_filesize(fd_t fd) {
#  pragma message "WARNING: internal_filesize is not implemented for WOS."
  hcf();
  //   struct stat st;
  //   if (internal_fstat(fd, &st))
  //     return -1;
  //   return (uptr)st.st_size;
}

uptr internal_dup(int oldfd) {
#  pragma message "WARNING: internal_dup is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(dup), oldfd);
}

uptr internal_dup2(int oldfd, int newfd) {
#  pragma message "WARNING: internal_dup2 is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(dup3), oldfd, newfd, 0);
}

uptr internal_readlink(const char *path, char *buf, uptr bufsize) {
#  pragma message "WARNING: internal_readlink is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(readlinkat), AT_FDCWD, (uptr)path,
  //   (uptr)buf, bufsize);
}

uptr internal_unlink(const char *path) {
#  pragma message "WARNING: internal_unlink is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(unlinkat), AT_FDCWD, (uptr)path, 0);
}

uptr internal_rename(const char *oldpath, const char *newpath) {
#  pragma message "WARNING: internal_rename is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(renameat), AT_FDCWD, (uptr)oldpath,
  //   AT_FDCWD,
  //                          (uptr)newpath);
}

uptr internal_sched_yield() {
#  pragma message "WARNING: internal_sched_yield is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(sched_yield));
}

void internal_usleep(u64 useconds) {
#  pragma message "WARNING: internal_usleep is not implemented for WOS."
  hcf();
  //   struct timespec ts;
  //   ts.tv_sec = useconds / 1000000;
  //   ts.tv_nsec = (useconds % 1000000) * 1000;
  //   internal_syscall(SYSCALL(nanosleep), &ts, &ts);
}

uptr internal_execve(const char *filename, char *const argv[],
                     char *const envp[]) {
#  pragma message "WARNING: internal_execve is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(execve), (uptr)filename, (uptr)argv,
  //                          (uptr)envp);
}

void internal__exit(int exitcode) {
#  pragma message "WARNING: internal__exit is not implemented for WOS."
  hcf();
  //   internal_syscall(SYSCALL(exit_group), exitcode);
  //   Die();  // Unreachable.
}

// ----------------- sanitizer_common.h
bool FileExists(const char *filename) {
  if (ShouldMockFailureToOpen(filename))
    return false;
  struct stat st;
  if (internal_stat(filename, &st))
    return false;
  // Sanity check: filename is a regular file.
  return S_ISREG(st.st_mode);
}

bool DirExists(const char *path) {
  struct stat st;
  if (internal_stat(path, &st))
    return false;
  return S_ISDIR(st.st_mode);
}

tid_t GetTid() {
#  pragma message "WARNING: GetTid is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(gettid));
}

int TgKill(pid_t pid, tid_t tid, int sig) {
#  pragma message "WARNING: TgKill is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(tgkill), pid, tid, sig);
}

u64 NanoTime() {
#  pragma message "WARNING: NanoTime is not implemented for WOS."
  hcf();
  //   kernel_timeval tv;
  //   internal_memset(&tv, 0, sizeof(tv));
  //   internal_syscall(SYSCALL(gettimeofday), &tv, 0);
  //   return (u64)tv.tv_sec * 1000 * 1000 * 1000 + tv.tv_usec * 1000;
}
// Used by real_clock_gettime.
uptr internal_clock_gettime(__sanitizer_clockid_t clk_id, void *tp) {
#  pragma message "WARNING: internal_clock_gettime is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(clock_gettime), clk_id, tp);
}

// Like getenv, but reads env directly from /proc (on Linux) or parses the
// 'environ' array (on some others) and does not use libc. This function
// should be called first inside __asan_init.
const char *GetEnv(const char *name) {
  static char *environ;
  static uptr len;
  static bool inited;
  if (!inited) {
    inited = true;
    uptr environ_size;
    if (!ReadFileToBuffer("/proc/self/environ", &environ, &environ_size, &len))
      environ = nullptr;
  }
  if (!environ || len == 0)
    return nullptr;
  uptr namelen = internal_strlen(name);
  const char *p = environ;
  while (*p != '\0') {  // will happen at the \0\0 that terminates the buffer
    // proc file has the format NAME=value\0NAME=value\0NAME=value\0...
    const char *endp = (char *)internal_memchr(p, '\0', len - (p - environ));
    if (!endp)  // this entry isn't NUL terminated
      return nullptr;
    else if (!internal_memcmp(p, name, namelen) && p[namelen] == '=')  // Match.
      return p + namelen + 1;  // point after =
    p = endp + 1;
  }
  return nullptr;  // Not found.
}

extern "C" {
SANITIZER_WEAK_ATTRIBUTE extern void *__libc_stack_end;
}

static void ReadNullSepFileToArray(const char *path, char ***arr,
                                   int arr_size) {
  char *buff;
  uptr buff_size;
  uptr buff_len;
  *arr = (char **)MmapOrDie(arr_size * sizeof(char *), "NullSepFileArray");
  if (!ReadFileToBuffer(path, &buff, &buff_size, &buff_len, 1024 * 1024)) {
    (*arr)[0] = nullptr;
    return;
  }
  (*arr)[0] = buff;
  int count, i;
  for (count = 1, i = 1;; i++) {
    if (buff[i] == 0) {
      if (buff[i + 1] == 0)
        break;
      (*arr)[count] = &buff[i + 1];
      CHECK_LE(count, arr_size - 1);  // FIXME: make this more flexible.
      count++;
    }
  }
  (*arr)[count] = nullptr;
}

static void GetArgsAndEnv(char ***argv, char ***envp) {
  if (&__libc_stack_end) {
    uptr *stack_end = (uptr *)__libc_stack_end;
    // Normally argc can be obtained from *stack_end, however, on ARM glibc's
    // _start clobbers it:
    // https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/arm/start.S;hb=refs/heads/release/2.31/master#l75
    // Do not special-case ARM and infer argc from argv everywhere.
    int argc = 0;
    while (stack_end[argc + 1]) argc++;
    *argv = (char **)(stack_end + 1);
    *envp = (char **)(stack_end + argc + 2);
  } else {
    static const int kMaxArgv = 2000, kMaxEnvp = 2000;
    ReadNullSepFileToArray("/proc/self/cmdline", argv, kMaxArgv);
    ReadNullSepFileToArray("/proc/self/environ", envp, kMaxEnvp);
  }
}

char **GetArgv() {
  char **argv, **envp;
  GetArgsAndEnv(&argv, &envp);
  return argv;
}

char **GetEnviron() {
  char **argv, **envp;
  GetArgsAndEnv(&argv, &envp);
  return envp;
}

void FutexWait(atomic_uint32_t *p, u32 cmp) {
#  pragma message "WARNING: FutexWait is not implemented for WOS."
  hcf();
  //   internal_syscall(SYSCALL(futex), (uptr)p, FUTEX_WAIT_PRIVATE, cmp, 0, 0,
  //   0);
}

void FutexWake(atomic_uint32_t *p, u32 count) {
#  pragma message "WARNING: FutexWake is not implemented for WOS."
  hcf();
  //   internal_syscall(SYSCALL(futex), (uptr)p, FUTEX_WAKE_PRIVATE, count, 0,
  //   0, 0);
}

// ----------------- sanitizer_wos.h
// The actual size of this structure is specified by d_reclen.
// Note that getdents64 uses a different structure format. We only provide the
// 32-bit syscall here.
struct wos_dirent {
  // inode
  u64 d_ino;
  // offset
  u64 d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[256];
};

// Syscall wrappers.
uptr internal_ptrace(int request, int pid, void *addr, void *data) {
#  pragma message "WARNING: internal_ptrace is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(ptrace), request, pid, (uptr)addr,
  //                          (uptr)data);
}

uptr internal_waitpid(int pid, int *status, int options) {
#  pragma message "WARNING: internal_waitpid is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(wait4), pid, (uptr)status, options,
  //                          0 /* rusage */);
}

uptr internal_getpid() {
#  pragma message "WARNING: internal_getpid is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(getpid));
}

uptr internal_getppid() {
#  pragma message "WARNING: internal_getppid is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(getppid));
}

uptr internal_getdents(fd_t fd, struct wos_dirent *dirp, unsigned int count) {
#  pragma message "WARNING: internal_getdents is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(getdents64), fd, (uptr)dirp, count);
}

uptr internal_lseek(fd_t fd, OFF_T offset, int whence) {
#  pragma message "WARNING: internal_lseek is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(lseek), fd, offset, whence);
}

// #  include <syscallnos.h>
uptr internal_prctl(int option, uptr arg2, uptr arg3, uptr arg4, uptr arg5) {
#  pragma message "WARNING: internal_prctl is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(prctl), option, arg2, arg3, arg4, arg5);
}
// Currently internal_arch_prctl() is only needed on x86_64.
uptr internal_arch_prctl(int option, uptr arg2) {
#  pragma message "WARNING: internal_arch_prctl is not implemented for WOS."
  hcf();
  //   return internal_syscall(__NR_arch_prctl, option, arg2);
}

uptr internal_sigaltstack(const void *ss, void *oss) {
#  pragma message "WARNING: internal_sigaltstack is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(sigaltstack), (uptr)ss, (uptr)oss);
}

extern "C" pid_t __fork(void);

int internal_fork() {
#  pragma message "WARNING: internal_fork is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(clone), SIGCHLD, 0);
}

#  define SA_RESTORER 0x04000000
// Doesn't set sa_restorer if the caller did not set it, so use with caution
//(see below).
int internal_sigaction_norestorer(int signum, const void *act, void *oldact) {
#  pragma message \
      "WARNING: internal_sigaction_norestorer is not implemented for WOS."
  hcf();
  //   __sanitizer_kernel_sigaction_t k_act, k_oldact;
  //   internal_memset(&k_act, 0, sizeof(__sanitizer_kernel_sigaction_t));
  //   internal_memset(&k_oldact, 0, sizeof(__sanitizer_kernel_sigaction_t));
  //   const __sanitizer_sigaction *u_act = (const __sanitizer_sigaction *)act;
  //   __sanitizer_sigaction *u_oldact = (__sanitizer_sigaction *)oldact;
  //   if (u_act) {
  //     k_act.handler = u_act->handler;
  //     k_act.sigaction = u_act->sigaction;
  //     internal_memcpy(&k_act.sa_mask, &u_act->sa_mask,
  //                     sizeof(__sanitizer_kernel_sigset_t));
  //     // Without SA_RESTORER kernel ignores the calls (probably returns
  //     EINVAL). k_act.sa_flags = u_act->sa_flags | SA_RESTORER;
  //     // FIXME: most often sa_restorer is unset, however the kernel requires
  //     it
  //     // to point to a valid signal restorer that calls the rt_sigreturn
  //     syscall.
  //     // If sa_restorer passed to the kernel is NULL, the program may crash
  //     upon
  //     // signal delivery or fail to unwind the stack in the signal handler.
  //     // libc implementation of sigaction() passes its own restorer to
  //     // rt_sigaction, so we need to do the same (we'll need to reimplement
  //     the
  //     // restorers; for x86_64 the restorer address can be obtained from
  //     // oldact->sa_restorer upon a call to sigaction(xxx, NULL, oldact).
  //     k_act.sa_restorer = u_act->sa_restorer;
  //   }
  //
  //   uptr result = internal_syscall(SYSCALL(rt_sigaction), (uptr)signum,
  //                                  (uptr)(u_act ? &k_act : nullptr),
  //                                  (uptr)(u_oldact ? &k_oldact : nullptr),
  //                                  (uptr)sizeof(__sanitizer_kernel_sigset_t));
  //
  //   if ((result == 0) && u_oldact) {
  //     u_oldact->handler = k_oldact.handler;
  //     u_oldact->sigaction = k_oldact.sigaction;
  //     internal_memcpy(&u_oldact->sa_mask, &k_oldact.sa_mask,
  //                     sizeof(__sanitizer_kernel_sigset_t));
  //     u_oldact->sa_flags = k_oldact.sa_flags;
  //     u_oldact->sa_restorer = k_oldact.sa_restorer;
  //   }
  //   return result;
}

uptr internal_sigprocmask(int how, __sanitizer_sigset_t *set,
                          __sanitizer_sigset_t *oldset) {
#  pragma message "WARNING: internal_sigprocmask is not implemented for WOS."
  hcf();
  //   __sanitizer_kernel_sigset_t *k_set = (__sanitizer_kernel_sigset_t *)set;
  //   __sanitizer_kernel_sigset_t *k_oldset = (__sanitizer_kernel_sigset_t
  //   *)oldset; return internal_syscall(SYSCALL(rt_sigprocmask), (uptr)how,
  //   (uptr)k_set,
  //                          (uptr)k_oldset,
  //                          sizeof(__sanitizer_kernel_sigset_t));
}

void internal_sigfillset(__sanitizer_sigset_t *set) {
  internal_memset(set, 0xff, sizeof(*set));
}

void internal_sigemptyset(__sanitizer_sigset_t *set) {
  internal_memset(set, 0, sizeof(*set));
}

void internal_sigdelset(__sanitizer_sigset_t *set, int signum) {
  signum -= 1;
  CHECK_GE(signum, 0);
  CHECK_LT(signum, sizeof(*set) * 8);
  __sanitizer_kernel_sigset_t *k_set = (__sanitizer_kernel_sigset_t *)set;
  const uptr idx = signum / (sizeof(k_set->sig[0]) * 8);
  const uptr bit = signum % (sizeof(k_set->sig[0]) * 8);
  k_set->sig[idx] &= ~((uptr)1 << bit);
}

bool internal_sigismember(__sanitizer_sigset_t *set, int signum) {
  signum -= 1;
  CHECK_GE(signum, 0);
  CHECK_LT(signum, sizeof(*set) * 8);
  __sanitizer_kernel_sigset_t *k_set = (__sanitizer_kernel_sigset_t *)set;
  const uptr idx = signum / (sizeof(k_set->sig[0]) * 8);
  const uptr bit = signum % (sizeof(k_set->sig[0]) * 8);
  return k_set->sig[idx] & ((uptr)1 << bit);
}

// ThreadLister implementation.
ThreadLister::ThreadLister(pid_t pid) : buffer_(4096) {
  task_path_.AppendF("/proc/%d/task", pid);
}

ThreadLister::Result ThreadLister::ListThreads(
    InternalMmapVector<tid_t> *threads) {
  int descriptor = internal_open(task_path_.data(), O_RDONLY | O_DIRECTORY);
  if (internal_iserror(descriptor)) {
    Report("Can't open %s for reading.\n", task_path_.data());
    return Error;
  }
  auto cleanup = at_scope_exit([&] { internal_close(descriptor); });
  threads->clear();

  Result result = Ok;
  for (bool first_read = true;; first_read = false) {
    CHECK_GE(buffer_.size(), 4096);
    uptr read = internal_getdents(
        descriptor, (struct wos_dirent *)buffer_.data(), buffer_.size());
    if (!read)
      return result;
    if (internal_iserror(read)) {
      Report("Can't read directory entries from %s.\n", task_path_.data());
      return Error;
    }

    for (uptr begin = (uptr)buffer_.data(), end = begin + read; begin < end;) {
      struct wos_dirent *entry = (struct wos_dirent *)begin;
      begin += entry->d_reclen;
      if (entry->d_ino == 1) {
        // Inode 1 is for bad blocks and also can be a reason for early return.
        // Should be emitted if kernel tried to output terminating thread.
        // See proc_task_readdir implementation in Linux.
        result = Incomplete;
      }
      if (entry->d_ino && *entry->d_name >= '0' && *entry->d_name <= '9')
        threads->push_back(internal_atoll(entry->d_name));
    }

    // Now we are going to detect short-read or early EOF. In such cases Linux
    // can return inconsistent list with missing alive threads.
    // Code will just remember that the list can be incomplete but it will
    // continue reads to return as much as possible.
    if (!first_read) {
      // The first one was a short-read by definition.
      result = Incomplete;
    } else if (read > buffer_.size() - 1024) {
      // Read was close to the buffer size. So double the size and assume the
      // worst.
      buffer_.resize(buffer_.size() * 2);
      result = Incomplete;
    } else if (!threads->empty() && !IsAlive(threads->back())) {
      // Maybe Linux early returned from read on terminated thread (!pid_alive)
      // and failed to restore read position.
      // See next_tid and proc_task_instantiate in Linux.
      result = Incomplete;
    }
  }
}

const char *ThreadLister::LoadStatus(tid_t tid) {
  status_path_.clear();
  status_path_.AppendF("%s/%llu/status", task_path_.data(), tid);
  auto cleanup = at_scope_exit([&] {
    // Resize back to capacity if it is downsized by `ReadFileToVector`.
    buffer_.resize(buffer_.capacity());
  });
  if (!ReadFileToVector(status_path_.data(), &buffer_) || buffer_.empty())
    return nullptr;
  buffer_.push_back('\0');
  return buffer_.data();
}

bool ThreadLister::IsAlive(tid_t tid) {
  // /proc/%d/task/%d/status uses same call to detect alive threads as
  // proc_task_readdir. See task_state implementation in Linux.
  static const char kPrefix[] = "\nPPid:";
  const char *status = LoadStatus(tid);
  if (!status)
    return false;
  const char *field = internal_strstr(status, kPrefix);
  if (!field)
    return false;
  field += internal_strlen(kPrefix);
  return (int)internal_atoll(field) != 0;
}

uptr GetMaxVirtualAddress() {
  return (1ULL << 47) - 1;  // 0x00007fffffffffffUL;
}

uptr GetMaxUserVirtualAddress() {
  uptr addr = GetMaxVirtualAddress();
  return addr;
}

uptr GetPageSize() { return EXEC_PAGESIZE; }

uptr ReadBinaryName(/*out*/ char *buf, uptr buf_len) {
  const char *default_module_name = "/proc/self/exe";
  uptr module_name_len = internal_readlink(default_module_name, buf, buf_len);
  int readlink_error;
  bool IsErr = internal_iserror(module_name_len, &readlink_error);
  if (IsErr) {
    // We can't read binary name for some reason, assume it's unknown.
    Report(
        "WARNING: reading executable name failed with errno %d, "
        "some stack frames may not be symbolized\n",
        readlink_error);
    module_name_len =
        internal_snprintf(buf, buf_len, "%s", default_module_name);
    CHECK_LT(module_name_len, buf_len);
  }
  return module_name_len;
}

uptr ReadLongProcessName(/*out*/ char *buf, uptr buf_len) {
  char *tmpbuf;
  uptr tmpsize;
  uptr tmplen;
  if (ReadFileToBuffer("/proc/self/cmdline", &tmpbuf, &tmpsize, &tmplen,
                       1024 * 1024)) {
    internal_strncpy(buf, tmpbuf, buf_len);
    UnmapOrDie(tmpbuf, tmpsize);
    return internal_strlen(buf);
  }
  return ReadBinaryName(buf, buf_len);
}

// Match full names of the form /path/to/base_name{-,.}*
bool LibraryNameIs(const char *full_name, const char *base_name) {
  const char *name = full_name;
  // Strip path.
  while (*name != '\0') name++;
  while (name > full_name && *name != '/') name--;
  if (*name == '/')
    name++;
  uptr base_name_length = internal_strlen(base_name);
  if (internal_strncmp(name, base_name, base_name_length))
    return false;
  return (name[base_name_length] == '-' || name[base_name_length] == '.');
}

// Call cb for each region mapped by map.
void ForEachMappedRegion(link_map *map, void (*cb)(const void *, uptr)) {
  CHECK_NE(map, nullptr);
  typedef ElfW(Phdr) Elf_Phdr;
  typedef ElfW(Ehdr) Elf_Ehdr;
  char *base = (char *)map->l_addr;
  Elf_Ehdr *ehdr = (Elf_Ehdr *)base;
  char *phdrs = base + ehdr->e_phoff;
  char *phdrs_end = phdrs + ehdr->e_phnum * ehdr->e_phentsize;

  // Find the segment with the minimum base so we can "relocate" the p_vaddr
  // fields.  Typically ET_DYN objects (DSOs) have base of zero and ET_EXEC
  // objects have a non-zero base.
  uptr preferred_base = (uptr)-1;
  for (char *iter = phdrs; iter != phdrs_end; iter += ehdr->e_phentsize) {
    Elf_Phdr *phdr = (Elf_Phdr *)iter;
    if (phdr->p_type == PT_LOAD && preferred_base > (uptr)phdr->p_vaddr)
      preferred_base = (uptr)phdr->p_vaddr;
  }

  // Compute the delta from the real base to get a relocation delta.
  sptr delta = (uptr)base - preferred_base;
  // Now we can figure out what the loader really mapped.
  for (char *iter = phdrs; iter != phdrs_end; iter += ehdr->e_phentsize) {
    Elf_Phdr *phdr = (Elf_Phdr *)iter;
    if (phdr->p_type == PT_LOAD) {
      uptr seg_start = phdr->p_vaddr + delta;
      uptr seg_end = seg_start + phdr->p_memsz;
      // None of these values are aligned.  We consider the ragged edges of the
      // load command as defined, since they are mapped from the file.
      seg_start = RoundDownTo(seg_start, GetPageSizeCached());
      seg_end = RoundUpTo(seg_end, GetPageSizeCached());
      cb((void *)seg_start, seg_end - seg_start);
    }
  }
}

// We cannot use glibc's clone wrapper, because it messes with the child
// task's TLS. It writes the PID and TID of the child task to its thread
// descriptor, but in our case the child task shares the thread descriptor with
// the parent (because we don't know how to allocate a new thread
// descriptor to keep glibc happy). So the stock version of clone(), when
// used with CLONE_VM, would end up corrupting the parent's thread descriptor.
uptr internal_clone(int (*fn)(void *), void *child_stack, int flags, void *arg,
                    int *parent_tidptr, void *newtls, int *child_tidptr) {
#  pragma message "WARNING: internal_clone is not implemented for WOS."
  hcf();
  //   long long res;
  //   if (!fn || !child_stack)
  //     return -EINVAL;
  //   CHECK_EQ(0, (uptr)child_stack % 16);
  //   child_stack = (char *)child_stack - 2 * sizeof(unsigned long long);
  //   ((unsigned long long *)child_stack)[0] = (uptr)fn;
  //   ((unsigned long long *)child_stack)[1] = (uptr)arg;
  //   register void *r8 __asm__("r8") = newtls;
  //   register int *r10 __asm__("r10") = child_tidptr;
  //   __asm__ __volatile__(
  //       /* %rax = syscall(%rax = SYSCALL(clone),
  //        *                %rdi = flags,
  //        *                %rsi = child_stack,
  //        *                %rdx = parent_tidptr,
  //        *                %r8  = new_tls,
  //        *                %r10 = child_tidptr)
  //        */
  //       "syscall\n"

  //       /* if (%rax != 0)
  //        *   return;
  //        */
  //       "testq  %%rax,%%rax\n"
  //       "jnz    1f\n"

  //       /* In the child. Terminate unwind chain. */
  //       // XXX: We should also terminate the CFI unwind chain
  //       // here. Unfortunately clang 3.2 doesn't support the
  //       // necessary CFI directives, so we skip that part.
  //       "xorq   %%rbp,%%rbp\n"

  //       /* Call "fn(arg)". */
  //       "popq   %%rax\n"
  //       "popq   %%rdi\n"
  //       "call   *%%rax\n"

  //       /* Call _exit(%rax). */
  //       "movq   %%rax,%%rdi\n"
  //       "movq   %2,%%rax\n"
  //       "syscall\n"

  //       /* Return to parent. */
  //       "1:\n"
  //       : "=a"(res)
  //       : "a"(SYSCALL(clone)), "i"(SYSCALL(exit)), "S"(child_stack),
  //       "D"(flags),
  //         "d"(parent_tidptr), "r"(r8), "r"(r10)
  //       : "memory", "r11", "rcx");
  //   return res;
}

int internal_uname(struct utsname *buf) {
#  pragma message "WARNING: internal_uname is not implemented for WOS."
  hcf();
  //   return internal_syscall(SYSCALL(uname), buf);
}

static HandleSignalMode GetHandleSignalModeImpl(int signum) {
  switch (signum) {
    case SIGABRT:
      return common_flags()->handle_abort;
    case SIGILL:
      return common_flags()->handle_sigill;
    case SIGTRAP:
      return common_flags()->handle_sigtrap;
    case SIGFPE:
      return common_flags()->handle_sigfpe;
    case SIGSEGV:
      return common_flags()->handle_segv;
    case SIGBUS:
      return common_flags()->handle_sigbus;
  }
  return kHandleSignalNo;
}

HandleSignalMode GetHandleSignalMode(int signum) {
  HandleSignalMode result = GetHandleSignalModeImpl(signum);
  if (result == kHandleSignalYes && !common_flags()->allow_user_segv_handler)
    return kHandleSignalExclusive;
  return result;
}

void *internal_start_thread(void *(*func)(void *arg), void *arg) {
  if (&internal_pthread_create == 0)
    return nullptr;
  // Start the thread with signals blocked, otherwise it can steal user signals.
  ScopedBlockSignals block(nullptr);
  void *th;
  internal_pthread_create(&th, nullptr, func, arg);
  return th;
}

void internal_join_thread(void *th) {
  if (&internal_pthread_join)
    internal_pthread_join(th, nullptr);
}

using Context = ucontext_t;

SignalContext::WriteFlag SignalContext::GetWriteFlag() const {
  Context *ucontext = (Context *)context;
  static const uptr PF_WRITE = 1U << 1;
  uptr err = ucontext->uc_mcontext.gregs[REG_ERR];
  return err & PF_WRITE ? Write : Read;
}

bool SignalContext::IsTrueFaultingAddress() const {
  auto si = static_cast<const siginfo_t *>(siginfo);
  // SIGSEGV signals without a true fault address have si_code set to 128.
  return si->si_signo == SIGSEGV && si->si_code != 128;
}

UNUSED
static const char *RegNumToRegName(int reg) {
  switch (reg) {
    case REG_RAX:
      return "rax";
    case REG_RBX:
      return "rbx";
    case REG_RCX:
      return "rcx";
    case REG_RDX:
      return "rdx";
    case REG_RDI:
      return "rdi";
    case REG_RSI:
      return "rsi";
    case REG_RBP:
      return "rbp";
    case REG_RSP:
      return "rsp";
    case REG_R8:
      return "r8";
    case REG_R9:
      return "r9";
    case REG_R10:
      return "r10";
    case REG_R11:
      return "r11";
    case REG_R12:
      return "r12";
    case REG_R13:
      return "r13";
    case REG_R14:
      return "r14";
    case REG_R15:
      return "r15";
    default:
      return NULL;
  }
  return NULL;
}

UNUSED
static void DumpSingleReg(ucontext_t *ctx, int RegNum) {
  const char *RegName = RegNumToRegName(RegNum);
  Printf("%s%s = 0x%016llx  ", internal_strlen(RegName) == 2 ? " " : "",
         RegName, ctx->uc_mcontext.gregs[RegNum]);
}

void SignalContext::DumpAllRegisters(void *context) {
  ucontext_t *ucontext = (ucontext_t *)context;
  Report("Register values:\n");
  DumpSingleReg(ucontext, REG_RAX);
  DumpSingleReg(ucontext, REG_RBX);
  DumpSingleReg(ucontext, REG_RCX);
  DumpSingleReg(ucontext, REG_RDX);
  Printf("\n");
  DumpSingleReg(ucontext, REG_RDI);
  DumpSingleReg(ucontext, REG_RSI);
  DumpSingleReg(ucontext, REG_RBP);
  DumpSingleReg(ucontext, REG_RSP);
  Printf("\n");
  DumpSingleReg(ucontext, REG_R8);
  DumpSingleReg(ucontext, REG_R9);
  DumpSingleReg(ucontext, REG_R10);
  DumpSingleReg(ucontext, REG_R11);
  Printf("\n");
  DumpSingleReg(ucontext, REG_R12);
  DumpSingleReg(ucontext, REG_R13);
  DumpSingleReg(ucontext, REG_R14);
  DumpSingleReg(ucontext, REG_R15);
  Printf("\n");
}

static void GetPcSpBp(void *context, uptr *pc, uptr *sp, uptr *bp) {
  ucontext_t *ucontext = (ucontext_t *)context;
  *pc = ucontext->uc_mcontext.gregs[REG_RIP];
  *bp = ucontext->uc_mcontext.gregs[REG_RBP];
  *sp = ucontext->uc_mcontext.gregs[REG_RSP];
}

void SignalContext::InitPcSpBp() { GetPcSpBp(context, &pc, &sp, &bp); }

void InitializePlatformEarly() { InitTlsSize(); }

void CheckASLR() {
  // Do nothing
  // TODO: remove me
}

void CheckMPROTECT() {
  // Do nothing
  // TODO: remove me
}

void CheckNoDeepBind(const char *filename, int flag) {
  if (flag & RTLD_DEEPBIND) {
    Report(
        "You are trying to dlopen a %s shared library with RTLD_DEEPBIND flag"
        " which is incompatible with sanitizer runtime "
        "(see https://github.com/google/sanitizers/issues/611 for details"
        "). If you want to run %s library under sanitizers please remove "
        "RTLD_DEEPBIND from dlopen flags.\n",
        filename, filename);
    Die();
  }
}

uptr FindAvailableMemoryRange(uptr size, uptr alignment, uptr left_padding,
                              uptr *largest_gap_found,
                              uptr *max_occupied_addr) {
  UNREACHABLE("FindAvailableMemoryRange is not available");
  return 0;
}

bool GetRandom(void *buffer, uptr length, bool blocking) {
#  pragma message "WARNING: GetRandom is not implemented for WOS."
  hcf();
  //   if (!buffer || !length || length > 256)
  //     return false;
  //   static atomic_uint8_t skip_getrandom_syscall;
  //   if (!atomic_load_relaxed(&skip_getrandom_syscall)) {
  //     // Up to 256 bytes, getrandom will not be interrupted.
  //     uptr res = internal_syscall(SYSCALL(getrandom), buffer, length,
  //                                 blocking ? 0 : GRND_NONBLOCK);
  //     int rverrno = 0;
  //     if (internal_iserror(res, &rverrno) && rverrno == ENOSYS)
  //       atomic_store_relaxed(&skip_getrandom_syscall, 1);
  //     else if (res == length)
  //       return true;
  //   }
  //   // Up to 256 bytes, a read off /dev/urandom will not be interrupted.
  //   // blocking is moot here, O_NONBLOCK has no effect when opening
  //   /dev/urandom. uptr fd = internal_open("/dev/urandom", O_RDONLY); if
  //   (internal_iserror(fd))
  //     return false;
  //   uptr res = internal_read(fd, buffer, length);
  //   if (internal_iserror(res))
  //     return false;
  //   internal_close(fd);
  //   return true;
}

}  // namespace __sanitizer

#endif  // SANITIZER_WOS
