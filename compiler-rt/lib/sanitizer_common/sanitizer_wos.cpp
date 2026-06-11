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
#  include <callnums/futex.h>
#  include <dlfcn.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <link.h>
#  include <pthread.h>
#  include <sched.h>
#  include <signal.h>
#  include <stdint.h>
#  include <sys/hcf.h>
#  include <sys/mman.h>
#  include <sys/multiproc.h>
#  include <sys/param.h>
#  include <sys/personality.h>
#  include <sys/process.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <sys/syscall.h>
#  include <sys/time.h>
#  include <sys/time_calls.h>
#  include <sys/time_ops.h>
#  include <sys/types.h>
#  include <sys/utsname.h>
#  include <sys/vfs.h>
#  include <ucontext.h>
#  include <unistd.h>

#  include "sanitizer_common.h"
#  include "sanitizer_flags.h"
#  include "sanitizer_getauxval.h"
#  include "sanitizer_internal_defs.h"
#  include "sanitizer_libc.h"
#  include "sanitizer_mutex.h"
#  include "sanitizer_placement_new.h"
#  include "sanitizer_posix.h"
#  include "sanitizer_procmaps.h"
#  include "sanitizer_wos.h"

extern char** environ;

struct kernel_timeval {
  long tv_sec;
  long tv_usec;
};

#  if !defined(GRND_NONBLOCK)
#    define GRND_NONBLOCK 1
#  endif
#  define SANITIZER_USE_GETRANDOM 1

namespace __sanitizer {

static uptr ToSanitizerResult(int64_t result) {
  return static_cast<uptr>(result);
}

enum class WosVmemOps : uint64_t {
  anon_allocate = 0,
  anon_free = 1,
  protect = 2,
  mremap = 3,
};

static int64_t WosVmemMap(void** out, void* hint, uptr size, int prot,
                          int flags, int fd, u64 offset) {
  uint64_t result =
      syscall(ker::abi::callnums::vmem_map, reinterpret_cast<uint64_t>(hint),
              static_cast<uint64_t>(size), static_cast<uint64_t>(prot),
              static_cast<uint64_t>(flags), static_cast<uint64_t>(fd), offset);
  auto signed_result = static_cast<int64_t>(result);
  if (signed_result < 0)
    return signed_result;
  *out = reinterpret_cast<void*>(result);
  return 0;
}

static int64_t WosVmemFree(void* addr, uptr size) {
  return static_cast<int64_t>(syscall(
      ker::abi::callnums::vmem, static_cast<uint64_t>(WosVmemOps::anon_free),
      reinterpret_cast<uint64_t>(addr), static_cast<uint64_t>(size), 0, 0));
}

static int64_t WosVmemProtect(void* addr, uptr size, int prot) {
  return static_cast<int64_t>(syscall(
      ker::abi::callnums::vmem, static_cast<uint64_t>(WosVmemOps::protect),
      reinterpret_cast<uint64_t>(addr), static_cast<uint64_t>(size),
      static_cast<uint64_t>(prot), 0));
}

static int64_t WosVmemRemap(void** out, void* old_addr, uptr old_size,
                            uptr new_size, int flags) {
  uint64_t result = syscall(
      ker::abi::callnums::vmem, static_cast<uint64_t>(WosVmemOps::mremap),
      reinterpret_cast<uint64_t>(old_addr), static_cast<uint64_t>(old_size),
      static_cast<uint64_t>(new_size), static_cast<uint64_t>(flags));
  auto signed_result = static_cast<int64_t>(result);
  if (signed_result < 0)
    return signed_result;
  *out = reinterpret_cast<void*>(result);
  return 0;
}

static int64_t WosFutexWait(int* addr, int expected) {
  return static_cast<int64_t>(syscall(
      ker::abi::callnums::futex,
      static_cast<uint64_t>(ker::abi::futex::futex_ops::FUTEX_WAIT),
      reinterpret_cast<uint64_t>(addr), static_cast<uint64_t>(expected), 0));
}

static int64_t WosFutexWake(int* addr) {
  return static_cast<int64_t>(
      syscall(ker::abi::callnums::futex,
              static_cast<uint64_t>(ker::abi::futex::futex_ops::FUTEX_WAKE),
              reinterpret_cast<uint64_t>(addr)));
}

void SetSigProcMask(__sanitizer_sigset_t* set, __sanitizer_sigset_t* oldset) {
  CHECK_EQ(0, internal_sigprocmask(SIG_SETMASK, set, oldset));
}

// Assume SANITIZER_LINUX
// Deletes the specified signal from newset, if it is not present in oldset
// Equivalently: newset[signum] = newset[signum] & oldset[signum]
static void KeepUnblocked(__sanitizer_sigset_t& newset,
                          __sanitizer_sigset_t& oldset, int signum) {
  // FIXME: https://github.com/google/sanitizers/issues/1816
  // Assume !SANITIZER_ANDROID
  if (!internal_sigismember(&oldset, signum))
    internal_sigdelset(&newset, signum);
}

// Block asynchronous signals
void BlockSignals(__sanitizer_sigset_t* oldset) {
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

ScopedBlockSignals::ScopedBlockSignals(__sanitizer_sigset_t* copy) {
  BlockSignals(&saved_);
  if (copy)
    internal_memcpy(copy, &saved_, sizeof(saved_));
}

ScopedBlockSignals::~ScopedBlockSignals() { SetSigProcMask(&saved_, nullptr); }

#  if defined(__x86_64__)
#    include "sanitizer_syscall_wos_x86_64.inc"
#  else
#    include "sanitizer_syscall_generic.inc"
#  endif

int internal_sigaction(int signum, const void* act, void* oldact) {
  return internal_sigaction_norestorer(signum, act, oldact);
}

// --------------- sanitizer_libc.h
uptr internal_mmap(void* addr, uptr length, int prot, int flags, int fd,
                   u64 offset) {
  void* result = nullptr;
  int64_t err = WosVmemMap(&result, addr, length, prot, flags, fd, offset);
  return err < 0 ? ToSanitizerResult(err) : reinterpret_cast<uptr>(result);
}

uptr internal_munmap(void* addr, uptr length) {
  return ToSanitizerResult(WosVmemFree(addr, length));
}

uptr internal_mremap(void* old_address, uptr old_size, uptr new_size, int flags,
                     void* new_address) {
  (void)new_address;
  void* result = nullptr;
  int64_t err = WosVmemRemap(&result, old_address, old_size, new_size, flags);
  return err < 0 ? ToSanitizerResult(err) : reinterpret_cast<uptr>(result);
}

int internal_mprotect(void* addr, uptr length, int prot) {
  return static_cast<int>(WosVmemProtect(addr, length, prot));
}

int internal_madvise(uptr addr, uptr length, int advice) {
  (void)addr;
  (void)length;
  (void)advice;
  return 0;
}

void UnmapFromTo(uptr from, uptr to) {
  if (to == from)
    return;
  CHECK(to >= from);
  uptr res = internal_munmap(reinterpret_cast<void*>(from), to - from);
  if (UNLIKELY(internal_iserror(res))) {
    Report("ERROR: %s failed to unmap 0x%zx (%zd) bytes at address %p\n",
           SanitizerToolName, to - from, to - from,
           reinterpret_cast<void*>(from));
    CHECK("unable to unmap" && 0);
  }
}

uptr MapDynamicShadow(uptr shadow_size_bytes, uptr shadow_scale,
                      uptr min_shadow_base_alignment, UNUSED uptr& high_mem_end,
                      uptr granularity) {
  const uptr alignment =
      Max<uptr>(granularity << shadow_scale, 1ULL << min_shadow_base_alignment);
  const uptr left_padding =
      Max<uptr>(granularity, 1ULL << min_shadow_base_alignment);

  const uptr shadow_size = RoundUpTo(shadow_size_bytes, granularity);
  const uptr map_size = shadow_size + left_padding + alignment;

  const uptr map_start = reinterpret_cast<uptr>(MmapNoAccess(map_size));
  CHECK_NE(map_start, static_cast<uptr>(-1));

  const uptr shadow_start = RoundUpTo(map_start + left_padding, alignment);

  UnmapFromTo(map_start, shadow_start - left_padding);
  UnmapFromTo(shadow_start + shadow_size, map_start + map_size);

  return shadow_start;
}

uptr internal_close(fd_t fd) {
  return ToSanitizerResult(ker::abi::vfs::close(fd));
}

uptr internal_open(const char* filename, int flags) {
  return ToSanitizerResult(ker::abi::vfs::open(filename, flags, 0));
}

uptr internal_open(const char* filename, int flags, u32 mode) {
  return ToSanitizerResult(ker::abi::vfs::open(filename, flags, mode));
}

uptr internal_read(fd_t fd, void* buf, uptr count) {
  return ToSanitizerResult(ker::abi::vfs::read(fd, buf, count));
}

uptr internal_write(fd_t fd, const void* buf, uptr count) {
  return ToSanitizerResult(ker::abi::vfs::write(fd, buf, count));
}

uptr internal_ftruncate(fd_t fd, uptr size) {
  return ToSanitizerResult(
      ker::abi::vfs::truncate(fd, static_cast<off_t>(size)));
}

uptr internal_stat(const char* path, void* buf) {
  return ToSanitizerResult(ker::abi::vfs::stat_path(path, buf));
}

uptr internal_lstat(const char* path, void* buf) {
  return ToSanitizerResult(ker::abi::vfs::lstat_path(path, buf));
}

uptr internal_fstat(fd_t fd, void* buf) {
  return ToSanitizerResult(ker::abi::vfs::fstat_fd(fd, buf));
}

uptr internal_filesize(fd_t fd) {
  struct stat st;
  if (internal_fstat(fd, &st))
    return static_cast<uptr>(-1);
  return static_cast<uptr>(st.st_size);
}

uptr internal_dup(int oldfd) {
  return ToSanitizerResult(ker::abi::vfs::dup(oldfd));
}

uptr internal_dup2(int oldfd, int newfd) {
  return ToSanitizerResult(ker::abi::vfs::dup2(oldfd, newfd));
}

uptr internal_readlink(const char* path, char* buf, uptr bufsize) {
  return ToSanitizerResult(ker::abi::vfs::readlink(path, buf, bufsize));
}

uptr internal_unlink(const char* path) {
  return ToSanitizerResult(ker::abi::vfs::unlink(path));
}

uptr internal_rename(const char* oldpath, const char* newpath) {
  return ToSanitizerResult(ker::abi::vfs::rename(oldpath, newpath));
}

uptr internal_sched_yield() {
  return ToSanitizerResult(static_cast<int64_t>(ker::multiproc::yield()));
}

void internal_usleep(u64 useconds) {
  struct timespec ts;
  ts.tv_sec = useconds / 1000000;
  ts.tv_nsec = (useconds % 1000000) * 1000;
  syscall(ker::abi::callnums::time,
          static_cast<uint64_t>(ker::abi::sys_time_ops::nanosleep),
          reinterpret_cast<uint64_t>(&ts), reinterpret_cast<uint64_t>(&ts));
}

uptr internal_execve(const char* filename, char* const argv[],
                     char* const envp[]) {
  return ToSanitizerResult(
      ker::process::execve(filename, const_cast<const char* const*>(argv),
                           const_cast<const char* const*>(envp)));
}

void internal__exit(int exitcode) {
  // WOS pthreads are represented as separate tasks.  The process EXIT syscall
  // currently terminates the calling task, so a sanitizer report from a worker
  // thread needs to wake and kill its siblings before exiting itself.
  uptr pid = static_cast<uptr>(ker::process::getpid());
  if (pid != 0)
    ker::process::kill(static_cast<int64_t>(pid), SIGKILL);
  ker::process::exit(static_cast<uint64_t>(exitcode));
  Trap();
  __builtin_unreachable();
}

// ----------------- sanitizer_common.h
bool FileExists(const char* filename) {
  if (ShouldMockFailureToOpen(filename))
    return false;
  struct stat st;
  if (internal_stat(filename, &st))
    return false;
  // Sanity check: filename is a regular file.
  return S_ISREG(st.st_mode);
}

bool DirExists(const char* path) {
  struct stat st;
  if (internal_stat(path, &st))
    return false;
  return S_ISDIR(st.st_mode);
}

ThreadID GetTid() {
  return static_cast<ThreadID>(ker::multiproc::currentThreadId());
}

int TgKill(pid_t pid, ThreadID tid, int sig) {
  (void)pid;
  return static_cast<int>(ker::process::kill(static_cast<int64_t>(tid), sig));
}

u64 NanoTime() {
  struct timeval tv;
  internal_memset(&tv, 0, sizeof(tv));
  ker::time::gettimeofday(&tv);
  return static_cast<u64>(tv.tv_sec) * 1000 * 1000 * 1000 +
         static_cast<u64>(tv.tv_usec) * 1000;
}

u64 MonotonicNanoTime() { return NanoTime(); }

void InitTlsSize() {}

uptr GetTlsSize() { return 0; }

static bool GetThreadStackFromPthread(uptr* stack_top, uptr* stack_bottom) {
  pthread_attr_t attr;
  if (pthread_attr_init(&attr) != 0)
    return false;

  int result = pthread_getattr_np(pthread_self(), &attr);
  if (result != 0) {
    pthread_attr_destroy(&attr);
    return false;
  }

  void* stack_addr = nullptr;
  uptr stack_size = 0;
  result = internal_pthread_attr_getstack(&attr, &stack_addr, &stack_size);
  pthread_attr_destroy(&attr);
  if (result != 0 || stack_addr == nullptr || stack_size == 0)
    return false;

  const uptr bottom = reinterpret_cast<uptr>(stack_addr);
  const uptr top = bottom + stack_size;
  const uptr marker = reinterpret_cast<uptr>(&result);
  if (top <= bottom || marker < bottom || marker >= top)
    return false;

  *stack_top = top;
  *stack_bottom = bottom;
  return true;
}

void GetThreadStackTopAndBottom(bool at_initialization, uptr* stack_top,
                                uptr* stack_bottom) {
  if (!at_initialization &&
      GetThreadStackFromPthread(stack_top, stack_bottom))
    return;

  uptr marker = reinterpret_cast<uptr>(&marker);
  MemoryMappingLayout proc_maps(/*cache_enabled=*/true);
  MemoryMappedSegment segment;
  while (!proc_maps.Error() && proc_maps.Next(&segment)) {
    if (marker >= segment.start && marker < segment.end) {
      *stack_top = segment.end;
      *stack_bottom = segment.start;
      return;
    }
  }
  *stack_top = 0;
  *stack_bottom = 0;
}

void GetThreadStackAndTls(bool main, uptr* stk_begin, uptr* stk_end,
                          uptr* tls_begin, uptr* tls_end) {
  (void)main;
  *tls_begin = 0;
  *tls_end = 0;

  uptr stack_top = 0;
  uptr stack_bottom = 0;
  GetThreadStackTopAndBottom(main, &stack_top, &stack_bottom);
  *stk_begin = stack_bottom;
  *stk_end = stack_top;
}

// Used by real_clock_gettime.
uptr internal_clock_gettime(__sanitizer_clockid_t clk_id, void* tp) {
  return ToSanitizerResult(static_cast<int64_t>(ker::time::clock_gettime(
      static_cast<int>(clk_id), reinterpret_cast<struct timespec*>(tp))));
}

// Like getenv, but reads env directly from /proc (on Linux) or parses the
// 'environ' array (on some others) and does not use libc. This function
// should be called first inside __asan_init.
const char* GetEnv(const char* name) {
  static char* environ;
  static uptr len;
  static bool inited;
  if (!inited) {
    inited = true;
    uptr environ_size;
    if (!ReadFileToBuffer("/proc/self/environ", &environ, &environ_size, &len))
      environ = nullptr;
  }
  uptr namelen = internal_strlen(name);
  if (!environ || len == 0) {
    for (char** envp = ::environ; envp != nullptr && *envp != nullptr; ++envp) {
      if (!internal_memcmp(*envp, name, namelen) && (*envp)[namelen] == '=')
        return *envp + namelen + 1;
    }
    return nullptr;
  }
  const char* p = environ;
  while (*p != '\0') {  // will happen at the \0\0 that terminates the buffer
    // proc file has the format NAME=value\0NAME=value\0NAME=value\0...
    const char* endp = (char*)internal_memchr(p, '\0', len - (p - environ));
    if (!endp)  // this entry isn't NUL terminated
      return nullptr;
    else if (!internal_memcmp(p, name, namelen) && p[namelen] == '=')  // Match.
      return p + namelen + 1;  // point after =
    p = endp + 1;
  }
  return nullptr;  // Not found.
}

extern "C" {
SANITIZER_WEAK_ATTRIBUTE extern void* __libc_stack_end;
}

static void ReadNullSepFileToArray(const char* path, char*** arr,
                                   int arr_size) {
  char* buff;
  uptr buff_size;
  uptr buff_len;
  *arr = (char**)MmapOrDie(arr_size * sizeof(char*), "NullSepFileArray");
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

static void GetArgsAndEnv(char*** argv, char*** envp) {
  if (&__libc_stack_end) {
    uptr* stack_end = (uptr*)__libc_stack_end;
    // Normally argc can be obtained from *stack_end, however, on ARM glibc's
    // _start clobbers it:
    // https://sourceware.org/git/?p=glibc.git;a=blob;f=sysdeps/arm/start.S;hb=refs/heads/release/2.31/master#l75
    // Do not special-case ARM and infer argc from argv everywhere.
    int argc = 0;
    while (stack_end[argc + 1]) argc++;
    *argv = (char**)(stack_end + 1);
    *envp = (char**)(stack_end + argc + 2);
  } else {
    static const int kMaxArgv = 2000, kMaxEnvp = 2000;
    ReadNullSepFileToArray("/proc/self/cmdline", argv, kMaxArgv);
    ReadNullSepFileToArray("/proc/self/environ", envp, kMaxEnvp);
  }
}

char** GetArgv() {
  char **argv, **envp;
  GetArgsAndEnv(&argv, &envp);
  return argv;
}

char** GetEnviron() {
  char **argv, **envp;
  GetArgsAndEnv(&argv, &envp);
  return envp;
}

void FutexWait(atomic_uint32_t* p, u32 cmp) {
  WosFutexWait(reinterpret_cast<int*>(p), static_cast<int>(cmp));
}

void FutexWake(atomic_uint32_t* p, u32 count) {
  for (u32 i = 0; i < count; ++i) WosFutexWake(reinterpret_cast<int*>(p));
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
uptr internal_ptrace(int request, int pid, void* addr, void* data) {
  return ToSanitizerResult(ker::process::ptrace(
      static_cast<uint64_t>(request), static_cast<uint64_t>(pid),
      reinterpret_cast<uint64_t>(addr), reinterpret_cast<uint64_t>(data)));
}

uptr internal_waitpid(int pid, int* status, int options) {
  return ToSanitizerResult(
      ker::process::waitpid(pid, status, options, nullptr));
}

uptr internal_getpid() { return static_cast<uptr>(ker::process::getpid()); }

uptr internal_getppid() { return static_cast<uptr>(ker::process::getppid()); }

uptr internal_getdents(fd_t fd, struct wos_dirent* dirp, unsigned int count) {
  return ToSanitizerResult(ker::abi::vfs::read_dir_entries(fd, dirp, count));
}

uptr internal_lseek(fd_t fd, OFF_T offset, int whence) {
  return ToSanitizerResult(ker::abi::vfs::lseek(fd, offset, whence));
}

// #  include <syscallnos.h>
uptr internal_prctl(int option, uptr arg2, uptr arg3, uptr arg4, uptr arg5) {
  return ToSanitizerResult(ker::process::prctl(
      option, static_cast<uint64_t>(arg2), static_cast<uint64_t>(arg3),
      static_cast<uint64_t>(arg4), static_cast<uint64_t>(arg5)));
}
// Currently internal_arch_prctl() is only needed on x86_64.
uptr internal_arch_prctl(int option, uptr arg2) {
  return ToSanitizerResult(
      ker::process::arch_prctl(option, static_cast<uint64_t>(arg2)));
}

uptr internal_sigaltstack(const void* ss, void* oss) {
  return ToSanitizerResult(ker::process::sigaltstack(ss, oss));
}

extern "C" pid_t __fork(void);

int internal_fork() { return static_cast<int>(ker::process::fork()); }

#  define SA_RESTORER 0x04000000
// Doesn't set sa_restorer if the caller did not set it, so use with caution
//(see below).
int internal_sigaction_norestorer(int signum, const void* act, void* oldact) {
  return static_cast<int>(ker::process::sigaction(signum, act, oldact));
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

uptr internal_sigprocmask(int how, __sanitizer_sigset_t* set,
                          __sanitizer_sigset_t* oldset) {
  return ToSanitizerResult(ker::process::sigprocmask(how, set, oldset));
}

void internal_sigfillset(__sanitizer_sigset_t* set) {
  internal_memset(set, 0xff, sizeof(*set));
}

void internal_sigemptyset(__sanitizer_sigset_t* set) {
  internal_memset(set, 0, sizeof(*set));
}

void internal_sigdelset(__sanitizer_sigset_t* set, int signum) {
  signum -= 1;
  CHECK_GE(signum, 0);
  CHECK_LT(signum, sizeof(*set) * 8);
  __sanitizer_kernel_sigset_t* k_set = (__sanitizer_kernel_sigset_t*)set;
  const uptr idx = signum / (sizeof(k_set->sig[0]) * 8);
  const uptr bit = signum % (sizeof(k_set->sig[0]) * 8);
  k_set->sig[idx] &= ~((uptr)1 << bit);
}

bool internal_sigismember(__sanitizer_sigset_t* set, int signum) {
  signum -= 1;
  CHECK_GE(signum, 0);
  CHECK_LT(signum, sizeof(*set) * 8);
  __sanitizer_kernel_sigset_t* k_set = (__sanitizer_kernel_sigset_t*)set;
  const uptr idx = signum / (sizeof(k_set->sig[0]) * 8);
  const uptr bit = signum % (sizeof(k_set->sig[0]) * 8);
  return k_set->sig[idx] & ((uptr)1 << bit);
}

// ThreadLister implementation.
ThreadLister::ThreadLister(pid_t pid) : buffer_(4096) {
  task_path_.AppendF("/proc/%d/task", pid);
}

ThreadLister::Result ThreadLister::ListThreads(
    InternalMmapVector<ThreadID>* threads) {
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
        descriptor, (struct wos_dirent*)buffer_.data(), buffer_.size());
    if (!read)
      return result;
    if (internal_iserror(read)) {
      Report("Can't read directory entries from %s.\n", task_path_.data());
      return Error;
    }

    for (uptr begin = (uptr)buffer_.data(), end = begin + read; begin < end;) {
      struct wos_dirent* entry = (struct wos_dirent*)begin;
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

const char* ThreadLister::LoadStatus(ThreadID tid) {
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

bool ThreadLister::IsAlive(ThreadID tid) {
  // /proc/%d/task/%d/status uses same call to detect alive threads as
  // proc_task_readdir. See task_state implementation in Linux.
  static const char kPrefix[] = "\nPPid:";
  const char* status = LoadStatus(tid);
  if (!status)
    return false;
  const char* field = internal_strstr(status, kPrefix);
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

uptr ReadBinaryName(/*out*/ char* buf, uptr buf_len) {
  const char* default_module_name = "/proc/self/exe";
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

uptr ReadLongProcessName(/*out*/ char* buf, uptr buf_len) {
  char* tmpbuf;
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
bool LibraryNameIs(const char* full_name, const char* base_name) {
  const char* name = full_name;
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

void ListOfModules::init() {
  clearOrInit();
  MemoryMappingLayout memory_mapping(/*cache_enabled=*/false);
  if (!memory_mapping.Error())
    memory_mapping.DumpListOfModules(&modules_);
}

void ListOfModules::fallbackInit() { clear(); }

// Call cb for each region mapped by map.
void ForEachMappedRegion(link_map* map, void (*cb)(const void*, uptr)) {
  CHECK_NE(map, nullptr);
  typedef ElfW(Phdr) Elf_Phdr;
  typedef ElfW(Ehdr) Elf_Ehdr;
  char* base = (char*)map->l_addr;
  Elf_Ehdr* ehdr = (Elf_Ehdr*)base;
  char* phdrs = base + ehdr->e_phoff;
  char* phdrs_end = phdrs + ehdr->e_phnum * ehdr->e_phentsize;

  // Find the segment with the minimum base so we can "relocate" the p_vaddr
  // fields.  Typically ET_DYN objects (DSOs) have base of zero and ET_EXEC
  // objects have a non-zero base.
  uptr preferred_base = (uptr)-1;
  for (char* iter = phdrs; iter != phdrs_end; iter += ehdr->e_phentsize) {
    Elf_Phdr* phdr = (Elf_Phdr*)iter;
    if (phdr->p_type == PT_LOAD && preferred_base > (uptr)phdr->p_vaddr)
      preferred_base = (uptr)phdr->p_vaddr;
  }

  // Compute the delta from the real base to get a relocation delta.
  sptr delta = (uptr)base - preferred_base;
  // Now we can figure out what the loader really mapped.
  for (char* iter = phdrs; iter != phdrs_end; iter += ehdr->e_phentsize) {
    Elf_Phdr* phdr = (Elf_Phdr*)iter;
    if (phdr->p_type == PT_LOAD) {
      uptr seg_start = phdr->p_vaddr + delta;
      uptr seg_end = seg_start + phdr->p_memsz;
      // None of these values are aligned.  We consider the ragged edges of the
      // load command as defined, since they are mapped from the file.
      seg_start = RoundDownTo(seg_start, GetPageSizeCached());
      seg_end = RoundUpTo(seg_end, GetPageSizeCached());
      cb((void*)seg_start, seg_end - seg_start);
    }
  }
}

// We cannot use glibc's clone wrapper, because it messes with the child
// task's TLS. It writes the PID and TID of the child task to its thread
// descriptor, but in our case the child task shares the thread descriptor with
// the parent (because we don't know how to allocate a new thread
// descriptor to keep glibc happy). So the stock version of clone(), when
// used with CLONE_VM, would end up corrupting the parent's thread descriptor.
uptr internal_clone(int (*fn)(void*), void* child_stack, int flags, void* arg,
                    int* parent_tidptr, void* newtls, int* child_tidptr) {
  if (fn == nullptr || child_stack == nullptr)
    return ToSanitizerResult(-EINVAL);
  ker::process::CloneVmArgs args = {};
  args.fn = reinterpret_cast<uint64_t>(fn);
  args.child_stack = reinterpret_cast<uint64_t>(child_stack);
  args.flags = static_cast<uint64_t>(flags);
  args.arg = reinterpret_cast<uint64_t>(arg);
  args.parent_tidptr = reinterpret_cast<uint64_t>(parent_tidptr);
  args.newtls = reinterpret_cast<uint64_t>(newtls);
  args.child_tidptr = reinterpret_cast<uint64_t>(child_tidptr);
  return ToSanitizerResult(ker::process::clone_vm(&args));
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

int internal_uname(struct utsname* buf) {
  if (buf == nullptr)
    return -EFAULT;
  return static_cast<int>(ker::process::uname(buf));
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

void* internal_start_thread(void* (*func)(void* arg), void* arg) {
  if (&internal_pthread_create == 0)
    return nullptr;
  // Start the thread with signals blocked, otherwise it can steal user signals.
  ScopedBlockSignals block(nullptr);
  void* th;
  internal_pthread_create(&th, nullptr, func, arg);
  return th;
}

void internal_join_thread(void* th) {
  if (&internal_pthread_join)
    internal_pthread_join(th, nullptr);
}

using Context = ucontext_t;

SignalContext::WriteFlag SignalContext::GetWriteFlag() const {
  Context* ucontext = (Context*)context;
  static const uptr PF_WRITE = 1U << 1;
  uptr err = ucontext->uc_mcontext.gregs[REG_ERR];
  return err & PF_WRITE ? Write : Read;
}

bool SignalContext::IsTrueFaultingAddress() const {
  auto si = static_cast<const siginfo_t*>(siginfo);
  // SIGSEGV signals without a true fault address have si_code set to 128.
  return si->si_signo == SIGSEGV && si->si_code != 128;
}

UNUSED
static const char* RegNumToRegName(int reg) {
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
static void DumpSingleReg(ucontext_t* ctx, int RegNum) {
  const char* RegName = RegNumToRegName(RegNum);
  Printf("%s%s = 0x%016llx  ", internal_strlen(RegName) == 2 ? " " : "",
         RegName, ctx->uc_mcontext.gregs[RegNum]);
}

void SignalContext::DumpAllRegisters(void* context) {
  ucontext_t* ucontext = (ucontext_t*)context;
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

static void GetPcSpBp(void* context, uptr* pc, uptr* sp, uptr* bp) {
  ucontext_t* ucontext = (ucontext_t*)context;
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

void InitializePlatformCommonFlags(CommonFlags* cf) { (void)cf; }

void CheckNoDeepBind(const char* filename, int flag) {
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
                              uptr* largest_gap_found,
                              uptr* max_occupied_addr) {
  UNREACHABLE("FindAvailableMemoryRange is not available");
  return 0;
}

bool GetRandom(void* buffer, uptr length, bool blocking) {
  (void)blocking;
  if (!buffer || !length || length > 256)
    return false;

  uptr fd = internal_open("/dev/urandom", O_RDONLY);
  if (internal_iserror(fd))
    fd = internal_open("/dev/random", O_RDONLY);
  if (internal_iserror(fd))
    return false;

  uptr res = internal_read(static_cast<fd_t>(fd), buffer, length);
  internal_close(static_cast<fd_t>(fd));
  return res == length;
}

}  // namespace __sanitizer

#endif  // SANITIZER_WOS
