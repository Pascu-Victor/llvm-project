//===-- sanitizer_platform_limits_wos.cpp --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// WOS-specific constants and structure sizes used by sanitizer interceptors.
//
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"

#if SANITIZER_WOS

#  include <limits.h>
#  include <netinet/in.h>
#  include <pthread.h>
#  include <sched.h>
#  include <signal.h>
#  include <stdio.h>
#  include <sys/ioctl.h>
#  include <sys/resource.h>
#  include <sys/stat.h>
#  include <sys/time.h>
#  include <sys/times.h>
#  include <sys/utsname.h>
#  include <wchar.h>

#  include "sanitizer_platform_limits_wos.h"

namespace __sanitizer {

unsigned struct_utsname_sz = sizeof(struct utsname);
unsigned struct_stat_sz = sizeof(struct stat);
unsigned struct_rusage_sz = sizeof(struct rusage);
unsigned siginfo_t_sz = sizeof(siginfo_t);
unsigned struct_itimerval_sz = sizeof(struct itimerval);
unsigned pthread_t_sz = sizeof(pthread_t);
unsigned mbstate_t_sz = sizeof(mbstate_t);
unsigned struct_tms_sz = sizeof(struct tms);
unsigned struct_stack_t_sz = sizeof(stack_t);
unsigned struct_sched_param_sz = sizeof(struct sched_param);
unsigned path_max = PATH_MAX;
unsigned fpos_t_sz = sizeof(fpos_t);

const uptr sig_ign = reinterpret_cast<uptr>(SIG_IGN);
const uptr sig_dfl = reinterpret_cast<uptr>(SIG_DFL);
const uptr sig_err = reinterpret_cast<uptr>(SIG_ERR);
const uptr sa_siginfo = SA_SIGINFO;

int af_inet = AF_INET;
int af_inet6 = AF_INET6;

uptr __sanitizer_in_addr_sz(int af) {
  if (af == AF_INET)
    return sizeof(struct in_addr);
  if (af == AF_INET6)
    return sizeof(struct in6_addr);
  return 0;
}

const int si_SEGV_MAPERR = SEGV_MAPERR;
const int si_SEGV_ACCERR = SEGV_ACCERR;

}  // namespace __sanitizer

#endif  // SANITIZER_WOS
