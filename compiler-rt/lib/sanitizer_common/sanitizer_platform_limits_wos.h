//===-- sanitizer_platform_limits_wos.h ---------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of Sanitizer common code.
//
// Sizes and layouts of platform-specific POSIX data structures for Linux
// x86_64.
//===----------------------------------------------------------------------===//

#ifndef SANITIZER_PLATFORM_LIMITS_WOS_H
#define SANITIZER_PLATFORM_LIMITS_WOS_H

#if SANITIZER_WOS

#  include "sanitizer_internal_defs.h"
#  include "sanitizer_mallinfo.h"
#  include "sanitizer_platform.h"

#  define SANITIZER_HAS_STAT64 1
#  define SANITIZER_HAS_STATFS64 1

#  define GET_LINK_MAP_BY_DLOPEN_HANDLE(handle) ((link_map *)(handle))

namespace __sanitizer {
extern unsigned struct_utsname_sz;
extern unsigned struct_stat_sz;
#  if SANITIZER_HAS_STAT64
extern unsigned struct_stat64_sz;
#  endif
extern unsigned struct_rusage_sz;
extern unsigned siginfo_t_sz;
extern unsigned struct_itimerval_sz;
extern unsigned pthread_t_sz;
extern unsigned pthread_mutex_t_sz;
extern unsigned pthread_cond_t_sz;
extern unsigned pid_t_sz;
extern unsigned timeval_sz;
extern unsigned uid_t_sz;
extern unsigned gid_t_sz;
extern unsigned mbstate_t_sz;
extern unsigned struct_timezone_sz;
extern unsigned struct_tms_sz;
extern unsigned struct_itimerspec_sz;
extern unsigned struct_sigevent_sz;
extern unsigned struct_stack_t_sz;
extern unsigned struct_sched_param_sz;
#  if SANITIZER_HAS_STATFS64
extern unsigned struct_statfs64_sz;
#  endif
extern unsigned struct_regex_sz;
extern unsigned struct_regmatch_sz;

extern unsigned struct_fstab_sz;
extern unsigned struct_statfs_sz;
extern unsigned struct_sockaddr_sz;
unsigned ucontext_t_sz(void *uctx);

const unsigned struct_kernel_stat_sz = 144;
const unsigned struct_kernel_stat64_sz = 0;

struct __sanitizer_perf_event_attr {
  unsigned type;
  unsigned size;
  // More fields that vary with the kernel version.
};

extern unsigned struct_epoll_event_sz;
extern unsigned struct_sysinfo_sz;
extern unsigned __user_cap_header_struct_sz;
extern unsigned __user_cap_data_struct_sz(void *hdrp);
extern unsigned struct_new_utsname_sz;
extern unsigned struct_old_utsname_sz;
extern unsigned struct_oldold_utsname_sz;

const unsigned struct_kexec_segment_sz = 4 * sizeof(unsigned long);

const unsigned struct___old_kernel_stat_sz = 32;

extern unsigned struct_rlimit_sz;
extern unsigned struct_utimbuf_sz;
extern unsigned struct_timespec_sz;

struct __sanitizer_iocb {
  u64 aio_data;
  u32 aio_key_or_aio_reserved1;  // Simply crazy.
  u32 aio_reserved1_or_aio_key;  // Luckily, we don't need these.
  u16 aio_lio_opcode;
  s16 aio_reqprio;
  u32 aio_fildes;
  u64 aio_buf;
  u64 aio_nbytes;
  s64 aio_offset;
  u64 aio_reserved2;
  u64 aio_reserved3;
};

struct __sanitizer_io_event {
  u64 data;
  u64 obj;
  u64 res;
  u64 res2;
};

const unsigned iocb_cmd_pread = 0;
const unsigned iocb_cmd_pwrite = 1;
const unsigned iocb_cmd_preadv = 7;
const unsigned iocb_cmd_pwritev = 8;

struct __sanitizer___sysctl_args {
  int *name;
  int nlen;
  void *oldval;
  uptr *oldlenp;
  void *newval;
  uptr newlen;
  unsigned long ___unused[4];
};

const unsigned old_sigset_t_sz = sizeof(unsigned long);

struct __sanitizer_sem_t {
  uptr data[4];
};

extern unsigned struct_ustat_sz;
extern unsigned struct_rlimit64_sz;
extern unsigned struct_statvfs64_sz;

struct __sanitizer_ipc_perm {
  int __key;
  int uid;
  int gid;
  int cuid;
  int cgid;
  unsigned int mode;
  unsigned short __seq;
  unsigned short __pad2;
  unsigned long __unused1;
  unsigned long __unused2;
};

struct __sanitizer_shmid_ds {
  __sanitizer_ipc_perm shm_perm;
  uptr shm_segsz;
  uptr shm_atime;
  uptr shm_dtime;
  uptr shm_ctime;
  int shm_cpid;
  int shm_lpid;
  uptr shm_nattch;
  uptr __unused4;
  uptr __unused5;
};

extern unsigned struct_msqid_ds_sz;
extern unsigned struct_mq_attr_sz;
extern unsigned struct_timex_sz;
extern unsigned struct_statvfs_sz;

struct __sanitizer_iovec {
  void *iov_base;
  usize iov_len;
};

struct __sanitizer_ifaddrs {
  struct __sanitizer_ifaddrs *ifa_next;
  char *ifa_name;
  unsigned int ifa_flags;
  void *ifa_addr;     // (struct sockaddr *)
  void *ifa_netmask;  // (struct sockaddr *)
                      // This is a union on Linux.
#  ifdef ifa_dstaddr
#    undef ifa_dstaddr
#  endif
  void *ifa_dstaddr;  // (struct sockaddr *)
  void *ifa_data;
};

typedef unsigned __sanitizer_pthread_key_t;

struct __sanitizer_XDR {
  int x_op;
  void *x_ops;
  uptr x_public;
  uptr x_private;
  uptr x_base;
  unsigned x_handy;
};

const int __sanitizer_XDR_ENCODE = 0;
const int __sanitizer_XDR_DECODE = 1;
const int __sanitizer_XDR_FREE = 2;

struct __sanitizer_passwd {
  char *pw_name;
  char *pw_passwd;
  int pw_uid;
  int pw_gid;
  char *pw_gecos;
  char *pw_dir;
  char *pw_shell;
};

struct __sanitizer_group {
  char *gr_name;
  char *gr_passwd;
  int gr_gid;
  char **gr_mem;
};

typedef long __sanitizer_time_t;

typedef long __sanitizer_suseconds_t;

struct __sanitizer_timespec {
  __sanitizer_time_t tv_sec; /* seconds */
  u64 tv_nsec;               /* nanoseconds */
};

struct __sanitizer_itimerspec {
  struct __sanitizer_timespec it_interval; /* timer period */
  struct __sanitizer_timespec it_value;    /* timer expiration */
};

struct __sanitizer_timeval {
  __sanitizer_time_t tv_sec;
  __sanitizer_suseconds_t tv_usec;
};

struct __sanitizer_itimerval {
  struct __sanitizer_timeval it_interval;
  struct __sanitizer_timeval it_value;
};

struct __sanitizer_timeb {
  __sanitizer_time_t time;
  unsigned short millitm;
  short timezone;
  short dstflag;
};

struct __sanitizer_ether_addr {
  u8 octet[6];
};

struct __sanitizer_tm {
  int tm_sec;
  int tm_min;
  int tm_hour;
  int tm_mday;
  int tm_mon;
  int tm_year;
  int tm_wday;
  int tm_yday;
  int tm_isdst;
  long int tm_gmtoff;
  const char *tm_zone;
};

struct __sanitizer_mntent {
  char *mnt_fsname;
  char *mnt_dir;
  char *mnt_type;
  char *mnt_opts;
  int mnt_freq;
  int mnt_passno;
};

struct __sanitizer_file_handle {
  unsigned int handle_bytes;
  int handle_type;
  unsigned char f_handle[1];  // variable sized
};

// In POSIX, int msg_iovlen; socklen_t msg_controllen; socklen_t cmsg_len; but
// many implementations don't conform to the standard.
struct __sanitizer_msghdr {
  void *msg_name;
  unsigned msg_namelen;
  struct __sanitizer_iovec *msg_iov;
  uptr msg_iovlen;
  void *msg_control;
  uptr msg_controllen;
  int msg_flags;
};
struct __sanitizer_cmsghdr {
  uptr cmsg_len;
  int cmsg_level;
  int cmsg_type;
};

struct __sanitizer_mmsghdr {
  __sanitizer_msghdr msg_hdr;
  unsigned int msg_len;
};

struct __sanitizer_dirent {
  unsigned long long d_ino;
  unsigned long long d_off;
  unsigned short d_reclen;
  // more fields that we don't care about
};

struct __sanitizer_dirent64 {
  unsigned long long d_ino;
  unsigned long long d_off;
  unsigned short d_reclen;
  // more fields that we don't care about
};
extern unsigned struct_sock_fprog_sz;

// not (defined(__x86_64__) && !defined(_LP64))
typedef long __sanitizer_clock_t;

typedef int __sanitizer_clockid_t;
typedef unsigned long long __sanitizer_eventfd_t;

typedef unsigned __sanitizer___kernel_uid_t;
typedef unsigned __sanitizer___kernel_gid_t;
typedef long __sanitizer___kernel_off_t;

typedef unsigned short __sanitizer___kernel_old_uid_t;
typedef unsigned short __sanitizer___kernel_old_gid_t;

typedef long long __sanitizer___kernel_loff_t;
typedef struct {
  unsigned long fds_bits[1024 / (8 * sizeof(long))];
} __sanitizer___kernel_fd_set;

// This thing depends on the platform. We are only interested in the upper
// limit. Verified with a compiler assert in .cpp.
union __sanitizer_pthread_attr_t {
  char size[128];
  void *align;
};

struct __sanitizer_sigset_t {
  // The size is determined by looking at sizeof of real sigset_t on linux.
  uptr val[128 / sizeof(uptr)];
};

struct __sanitizer_siginfo_pad {
  // Require uptr, because siginfo_t is always pointer-size aligned on Linux.
  uptr pad[128 / sizeof(uptr)];
};

#  define SANITIZER_HAS_SIGINFO 1
union __sanitizer_siginfo {
  __extension__ struct {
    int si_signo;
    int si_errno;
    int si_code;
  };
  __sanitizer_siginfo_pad pad;
};

using __sanitizer_sighandler_ptr = void (*)(int sig);
using __sanitizer_sigactionhandler_ptr = void (*)(int sig,
                                                  __sanitizer_siginfo *siginfo,
                                                  void *uctx);

// Linux system headers define the 'sa_handler' and 'sa_sigaction' macros.
struct __sanitizer_sigaction {
  union {
    __sanitizer_sigactionhandler_ptr sigaction;
    __sanitizer_sighandler_ptr handler;
  };
  __sanitizer_sigset_t sa_mask;
  int sa_flags;
  void (*sa_restorer)();
};

#  define __SANITIZER_KERNEL_NSIG 64

struct __sanitizer_kernel_sigset_t {
  uptr sig[__SANITIZER_KERNEL_NSIG / (sizeof(uptr) * 8)];
};

// Linux system headers define the 'sa_handler' and 'sa_sigaction' macros.
struct __sanitizer_kernel_sigaction_t {
  union {
    void (*handler)(int signo);
    void (*sigaction)(int signo, __sanitizer_siginfo *info, void *ctx);
  };
  unsigned long sa_flags;
  void (*sa_restorer)(void);
  __sanitizer_kernel_sigset_t sa_mask;
};

extern const uptr sig_ign;
extern const uptr sig_dfl;
extern const uptr sig_err;
extern const uptr sa_siginfo;

extern int e_tabsz;

extern int af_inet;
extern int af_inet6;
uptr __sanitizer_in_addr_sz(int af);

struct __sanitizer_dl_phdr_info {
  uptr dlpi_addr;
  const char *dlpi_name;
  const void *dlpi_phdr;
  short dlpi_phnum;
};

extern unsigned struct_ElfW_Phdr_sz;

struct __sanitizer_protoent {
  char *p_name;
  char **p_aliases;
  int p_proto;
};

struct __sanitizer_netent {
  char *n_name;
  char **n_aliases;
  int n_addrtype;
  u32 n_net;
};

struct __sanitizer_addrinfo {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  unsigned ai_addrlen;
  void *ai_addr;
  char *ai_canonname;
  struct __sanitizer_addrinfo *ai_next;
};

struct __sanitizer_hostent {
  char *h_name;
  char **h_aliases;
  int h_addrtype;
  int h_length;
  char **h_addr_list;
};

struct __sanitizer_pollfd {
  int fd;
  short events;
  short revents;
};

typedef unsigned long __sanitizer_nfds_t;

struct __sanitizer_glob_t {
  uptr gl_pathc;
  char **gl_pathv;
  uptr gl_offs;
  int gl_flags;

  void (*gl_closedir)(void *dirp);
  void *(*gl_readdir)(void *dirp);
  void *(*gl_opendir)(const char *);
  int (*gl_lstat)(const char *, void *);
  int (*gl_stat)(const char *, void *);
};

extern int glob_nomatch;
extern int glob_altdirfunc;

extern unsigned path_max;

extern const int wordexp_wrde_dooffs;

struct __sanitizer_wordexp_t {
  uptr we_wordc;
  char **we_wordv;
  uptr we_offs;
};

struct __sanitizer_FILE {
  int _flags;
  char *_IO_read_ptr;
  char *_IO_read_end;
  char *_IO_read_base;
  char *_IO_write_base;
  char *_IO_write_ptr;
  char *_IO_write_end;
  char *_IO_buf_base;
  char *_IO_buf_end;
  char *_IO_save_base;
  char *_IO_backup_base;
  char *_IO_save_end;
  void *_markers;
  __sanitizer_FILE *_chain;
  int _fileno;
};
#  define SANITIZER_HAS_STRUCT_FILE 1

extern unsigned struct_user_regs_struct_sz;
extern unsigned struct_user_fpregs_struct_sz;
extern unsigned struct_user_fpxregs_struct_sz;
extern unsigned struct_user_vfpregs_struct_sz;

extern int ptrace_peektext;
extern int ptrace_peekdata;
extern int ptrace_peekuser;
extern int ptrace_getregs;
extern int ptrace_setregs;
extern int ptrace_getfpregs;
extern int ptrace_setfpregs;
extern int ptrace_getfpxregs;
extern int ptrace_setfpxregs;
extern int ptrace_getvfpregs;
extern int ptrace_setvfpregs;
extern int ptrace_getsiginfo;
extern int ptrace_setsiginfo;
extern int ptrace_getregset;
extern int ptrace_setregset;
extern int ptrace_geteventmsg;

// Helper for the ptrace interceptor.
template <class T>
inline T ptrace_data_arg(int request, T addr, T data) {
  return data;
}

extern unsigned struct_shminfo_sz;
extern unsigned struct_shm_info_sz;
extern int shmctl_ipc_stat;
extern int shmctl_ipc_info;
extern int shmctl_shm_info;
extern int shmctl_shm_stat;

extern unsigned struct_utmp_sz;
extern unsigned struct_utmpx_sz;

extern int map_fixed;

// ioctl arguments
struct __sanitizer_ifconf {
  int ifc_len;
  union {
    void *ifcu_req;
  } ifc_ifcu;
};

struct __sanitizer__obstack_chunk {
  char *limit;
  struct __sanitizer__obstack_chunk *prev;
};

struct __sanitizer_obstack {
  long chunk_size;
  struct __sanitizer__obstack_chunk *chunk;
  char *object_base;
  char *next_free;
  uptr more_fields[7];
};

typedef uptr (*__sanitizer_cookie_io_read)(void *cookie, char *buf, uptr size);
typedef uptr (*__sanitizer_cookie_io_write)(void *cookie, const char *buf,
                                            uptr size);
typedef int (*__sanitizer_cookie_io_seek)(void *cookie, u64 *offset,
                                          int whence);
typedef int (*__sanitizer_cookie_io_close)(void *cookie);

struct __sanitizer_cookie_io_functions_t {
  __sanitizer_cookie_io_read read;
  __sanitizer_cookie_io_write write;
  __sanitizer_cookie_io_seek seek;
  __sanitizer_cookie_io_close close;
};

#  define IOC_NRBITS 8
#  define IOC_TYPEBITS 8
#  define IOC_SIZEBITS 14
#  define IOC_DIRBITS 2
#  define IOC_NONE 0U
#  define IOC_WRITE 1U
#  define IOC_READ 2U
#  define IOC_NRMASK ((1 << IOC_NRBITS) - 1)
#  define IOC_TYPEMASK ((1 << IOC_TYPEBITS) - 1)
#  define IOC_SIZEMASK ((1 << IOC_SIZEBITS) - 1)
#  if defined(IOC_DIRMASK)
#    undef IOC_DIRMASK
#  endif
#  define IOC_DIRMASK ((1 << IOC_DIRBITS) - 1)
#  define IOC_NRSHIFT 0
#  define IOC_TYPESHIFT (IOC_NRSHIFT + IOC_NRBITS)
#  define IOC_SIZESHIFT (IOC_TYPESHIFT + IOC_TYPEBITS)
#  define IOC_DIRSHIFT (IOC_SIZESHIFT + IOC_SIZEBITS)
#  define EVIOC_EV_MAX 0x1f
#  define EVIOC_ABS_MAX 0x3f

#  define IOC_DIR(nr) (((nr) >> IOC_DIRSHIFT) & IOC_DIRMASK)
#  define IOC_TYPE(nr) (((nr) >> IOC_TYPESHIFT) & IOC_TYPEMASK)
#  define IOC_NR(nr) (((nr) >> IOC_NRSHIFT) & IOC_NRMASK)

#  define IOC_SIZE(nr) (((nr) >> IOC_SIZESHIFT) & IOC_SIZEMASK)

extern unsigned struct_ifreq_sz;
extern unsigned struct_termios_sz;
extern unsigned struct_winsize_sz;

extern unsigned struct_arpreq_sz;
extern unsigned struct_cdrom_msf_sz;
extern unsigned struct_cdrom_multisession_sz;
extern unsigned struct_cdrom_read_audio_sz;
extern unsigned struct_cdrom_subchnl_sz;
extern unsigned struct_cdrom_ti_sz;
extern unsigned struct_cdrom_tocentry_sz;
extern unsigned struct_cdrom_tochdr_sz;
extern unsigned struct_cdrom_volctrl_sz;
extern unsigned struct_ff_effect_sz;
extern unsigned struct_floppy_drive_params_sz;
extern unsigned struct_floppy_drive_struct_sz;
extern unsigned struct_floppy_fdc_state_sz;
extern unsigned struct_floppy_max_errors_sz;
extern unsigned struct_floppy_raw_cmd_sz;
extern unsigned struct_floppy_struct_sz;
extern unsigned struct_floppy_write_errors_sz;
extern unsigned struct_format_descr_sz;
extern unsigned struct_hd_driveid_sz;
extern unsigned struct_hd_geometry_sz;
extern unsigned struct_input_absinfo_sz;
extern unsigned struct_input_id_sz;
extern unsigned struct_mtpos_sz;
extern unsigned struct_termio_sz;
extern unsigned struct_vt_consize_sz;
extern unsigned struct_vt_sizes_sz;
extern unsigned struct_vt_stat_sz;

extern unsigned struct_copr_buffer_sz;
extern unsigned struct_copr_debug_buf_sz;
extern unsigned struct_copr_msg_sz;
extern unsigned struct_midi_info_sz;
extern unsigned struct_mtget_sz;
extern unsigned struct_mtop_sz;
extern unsigned struct_rtentry_sz;
extern unsigned struct_sbi_instrument_sz;
extern unsigned struct_seq_event_rec_sz;
extern unsigned struct_synth_info_sz;
extern unsigned struct_vt_mode_sz;

extern unsigned struct_ax25_parms_struct_sz;
extern unsigned struct_input_keymap_entry_sz;
extern unsigned struct_ipx_config_data_sz;
extern unsigned struct_kbdiacrs_sz;
extern unsigned struct_kbentry_sz;
extern unsigned struct_kbkeycode_sz;
extern unsigned struct_kbsentry_sz;
extern unsigned struct_mtconfiginfo_sz;
extern unsigned struct_nr_parms_struct_sz;
extern unsigned struct_scc_modem_sz;
extern unsigned struct_scc_stat_sz;
extern unsigned struct_serial_multiport_struct_sz;
extern unsigned struct_serial_struct_sz;
extern unsigned struct_sockaddr_ax25_sz;
extern unsigned struct_unimapdesc_sz;
extern unsigned struct_unimapinit_sz;

extern const unsigned long __sanitizer_bufsiz;

extern unsigned struct_audio_buf_info_sz;
extern unsigned struct_ppp_stats_sz;

extern unsigned struct_sioc_sg_req_sz;
extern unsigned struct_sioc_vif_req_sz;

extern unsigned fpos_t_sz;

// A special value to mark ioctls that are not present on the target platform,
// when it can not be determined without including any system headers.
extern const unsigned IOCTL_NOT_PRESENT;

extern unsigned IOCTL_FIOASYNC;
extern unsigned IOCTL_FIOCLEX;
extern unsigned IOCTL_FIOGETOWN;
extern unsigned IOCTL_FIONBIO;
extern unsigned IOCTL_FIONCLEX;
extern unsigned IOCTL_FIOSETOWN;
extern unsigned IOCTL_SIOCADDMULTI;
extern unsigned IOCTL_SIOCATMARK;
extern unsigned IOCTL_SIOCDELMULTI;
extern unsigned IOCTL_SIOCGIFADDR;
extern unsigned IOCTL_SIOCGIFBRDADDR;
extern unsigned IOCTL_SIOCGIFCONF;
extern unsigned IOCTL_SIOCGIFDSTADDR;
extern unsigned IOCTL_SIOCGIFFLAGS;
extern unsigned IOCTL_SIOCGIFMETRIC;
extern unsigned IOCTL_SIOCGIFMTU;
extern unsigned IOCTL_SIOCGIFNETMASK;
extern unsigned IOCTL_SIOCGPGRP;
extern unsigned IOCTL_SIOCSIFADDR;
extern unsigned IOCTL_SIOCSIFBRDADDR;
extern unsigned IOCTL_SIOCSIFDSTADDR;
extern unsigned IOCTL_SIOCSIFFLAGS;
extern unsigned IOCTL_SIOCSIFMETRIC;
extern unsigned IOCTL_SIOCSIFMTU;
extern unsigned IOCTL_SIOCSIFNETMASK;
extern unsigned IOCTL_SIOCSPGRP;
extern unsigned IOCTL_TIOCCONS;
extern unsigned IOCTL_TIOCEXCL;
extern unsigned IOCTL_TIOCGETD;
extern unsigned IOCTL_TIOCGPGRP;
extern unsigned IOCTL_TIOCGWINSZ;
extern unsigned IOCTL_TIOCMBIC;
extern unsigned IOCTL_TIOCMBIS;
extern unsigned IOCTL_TIOCMGET;
extern unsigned IOCTL_TIOCMSET;
extern unsigned IOCTL_TIOCNOTTY;
extern unsigned IOCTL_TIOCNXCL;
extern unsigned IOCTL_TIOCOUTQ;
extern unsigned IOCTL_TIOCPKT;
extern unsigned IOCTL_TIOCSCTTY;
extern unsigned IOCTL_TIOCSETD;
extern unsigned IOCTL_TIOCSPGRP;
extern unsigned IOCTL_TIOCSTI;
extern unsigned IOCTL_TIOCSWINSZ;
extern unsigned IOCTL_SIOCGETSGCNT;
extern unsigned IOCTL_SIOCGETVIFCNT;
extern unsigned IOCTL_EVIOCGABS;
extern unsigned IOCTL_EVIOCGBIT;
extern unsigned IOCTL_EVIOCGEFFECTS;
extern unsigned IOCTL_EVIOCGID;
extern unsigned IOCTL_EVIOCGKEY;
extern unsigned IOCTL_EVIOCGKEYCODE;
extern unsigned IOCTL_EVIOCGLED;
extern unsigned IOCTL_EVIOCGNAME;
extern unsigned IOCTL_EVIOCGPHYS;
extern unsigned IOCTL_EVIOCGRAB;
extern unsigned IOCTL_EVIOCGREP;
extern unsigned IOCTL_EVIOCGSND;
extern unsigned IOCTL_EVIOCGSW;
extern unsigned IOCTL_EVIOCGUNIQ;
extern unsigned IOCTL_EVIOCGVERSION;
extern unsigned IOCTL_EVIOCRMFF;
extern unsigned IOCTL_EVIOCSABS;
extern unsigned IOCTL_EVIOCSFF;
extern unsigned IOCTL_EVIOCSKEYCODE;
extern unsigned IOCTL_EVIOCSREP;
extern unsigned IOCTL_BLKFLSBUF;
extern unsigned IOCTL_BLKGETSIZE;
extern unsigned IOCTL_BLKRAGET;
extern unsigned IOCTL_BLKRASET;
extern unsigned IOCTL_BLKROGET;
extern unsigned IOCTL_BLKROSET;
extern unsigned IOCTL_BLKRRPART;
extern unsigned IOCTL_BLKFRASET;
extern unsigned IOCTL_BLKFRAGET;
extern unsigned IOCTL_BLKSECTSET;
extern unsigned IOCTL_BLKSECTGET;
extern unsigned IOCTL_BLKSSZGET;
extern unsigned IOCTL_BLKBSZGET;
extern unsigned IOCTL_BLKBSZSET;
extern unsigned IOCTL_BLKGETSIZE64;
extern unsigned IOCTL_CDROMAUDIOBUFSIZ;
extern unsigned IOCTL_CDROMEJECT;
extern unsigned IOCTL_CDROMEJECT_SW;
extern unsigned IOCTL_CDROMMULTISESSION;
extern unsigned IOCTL_CDROMPAUSE;
extern unsigned IOCTL_CDROMPLAYMSF;
extern unsigned IOCTL_CDROMPLAYTRKIND;
extern unsigned IOCTL_CDROMREADAUDIO;
extern unsigned IOCTL_CDROMREADCOOKED;
extern unsigned IOCTL_CDROMREADMODE1;
extern unsigned IOCTL_CDROMREADMODE2;
extern unsigned IOCTL_CDROMREADRAW;
extern unsigned IOCTL_CDROMREADTOCENTRY;
extern unsigned IOCTL_CDROMREADTOCHDR;
extern unsigned IOCTL_CDROMRESET;
extern unsigned IOCTL_CDROMRESUME;
extern unsigned IOCTL_CDROMSEEK;
extern unsigned IOCTL_CDROMSTART;
extern unsigned IOCTL_CDROMSTOP;
extern unsigned IOCTL_CDROMSUBCHNL;
extern unsigned IOCTL_CDROMVOLCTRL;
extern unsigned IOCTL_CDROMVOLREAD;
extern unsigned IOCTL_CDROM_GET_UPC;
extern unsigned IOCTL_FDCLRPRM;
extern unsigned IOCTL_FDDEFPRM;
extern unsigned IOCTL_FDFLUSH;
extern unsigned IOCTL_FDFMTBEG;
extern unsigned IOCTL_FDFMTEND;
extern unsigned IOCTL_FDFMTTRK;
extern unsigned IOCTL_FDGETDRVPRM;
extern unsigned IOCTL_FDGETDRVSTAT;
extern unsigned IOCTL_FDGETDRVTYP;
extern unsigned IOCTL_FDGETFDCSTAT;
extern unsigned IOCTL_FDGETMAXERRS;
extern unsigned IOCTL_FDGETPRM;
extern unsigned IOCTL_FDMSGOFF;
extern unsigned IOCTL_FDMSGON;
extern unsigned IOCTL_FDPOLLDRVSTAT;
extern unsigned IOCTL_FDRAWCMD;
extern unsigned IOCTL_FDRESET;
extern unsigned IOCTL_FDSETDRVPRM;
extern unsigned IOCTL_FDSETEMSGTRESH;
extern unsigned IOCTL_FDSETMAXERRS;
extern unsigned IOCTL_FDSETPRM;
extern unsigned IOCTL_FDTWADDLE;
extern unsigned IOCTL_FDWERRORCLR;
extern unsigned IOCTL_FDWERRORGET;
extern unsigned IOCTL_HDIO_DRIVE_CMD;
extern unsigned IOCTL_HDIO_GETGEO;
extern unsigned IOCTL_HDIO_GET_32BIT;
extern unsigned IOCTL_HDIO_GET_DMA;
extern unsigned IOCTL_HDIO_GET_IDENTITY;
extern unsigned IOCTL_HDIO_GET_KEEPSETTINGS;
extern unsigned IOCTL_HDIO_GET_MULTCOUNT;
extern unsigned IOCTL_HDIO_GET_NOWERR;
extern unsigned IOCTL_HDIO_GET_UNMASKINTR;
extern unsigned IOCTL_HDIO_SET_32BIT;
extern unsigned IOCTL_HDIO_SET_DMA;
extern unsigned IOCTL_HDIO_SET_KEEPSETTINGS;
extern unsigned IOCTL_HDIO_SET_MULTCOUNT;
extern unsigned IOCTL_HDIO_SET_NOWERR;
extern unsigned IOCTL_HDIO_SET_UNMASKINTR;
extern unsigned IOCTL_MTIOCPOS;
extern unsigned IOCTL_PPPIOCGASYNCMAP;
extern unsigned IOCTL_PPPIOCGDEBUG;
extern unsigned IOCTL_PPPIOCGFLAGS;
extern unsigned IOCTL_PPPIOCGUNIT;
extern unsigned IOCTL_PPPIOCGXASYNCMAP;
extern unsigned IOCTL_PPPIOCSASYNCMAP;
extern unsigned IOCTL_PPPIOCSDEBUG;
extern unsigned IOCTL_PPPIOCSFLAGS;
extern unsigned IOCTL_PPPIOCSMAXCID;
extern unsigned IOCTL_PPPIOCSMRU;
extern unsigned IOCTL_PPPIOCSXASYNCMAP;
extern unsigned IOCTL_SIOCDARP;
extern unsigned IOCTL_SIOCDRARP;
extern unsigned IOCTL_SIOCGARP;
extern unsigned IOCTL_SIOCGIFENCAP;
extern unsigned IOCTL_SIOCGIFHWADDR;
extern unsigned IOCTL_SIOCGIFMAP;
extern unsigned IOCTL_SIOCGIFMEM;
extern unsigned IOCTL_SIOCGIFNAME;
extern unsigned IOCTL_SIOCGIFSLAVE;
extern unsigned IOCTL_SIOCGRARP;
extern unsigned IOCTL_SIOCGSTAMP;
extern unsigned IOCTL_SIOCSARP;
extern unsigned IOCTL_SIOCSIFENCAP;
extern unsigned IOCTL_SIOCSIFHWADDR;
extern unsigned IOCTL_SIOCSIFLINK;
extern unsigned IOCTL_SIOCSIFMAP;
extern unsigned IOCTL_SIOCSIFMEM;
extern unsigned IOCTL_SIOCSIFSLAVE;
extern unsigned IOCTL_SIOCSRARP;
extern unsigned IOCTL_SNDCTL_COPR_HALT;
extern unsigned IOCTL_SNDCTL_COPR_LOAD;
extern unsigned IOCTL_SNDCTL_COPR_RCODE;
extern unsigned IOCTL_SNDCTL_COPR_RCVMSG;
extern unsigned IOCTL_SNDCTL_COPR_RDATA;
extern unsigned IOCTL_SNDCTL_COPR_RESET;
extern unsigned IOCTL_SNDCTL_COPR_RUN;
extern unsigned IOCTL_SNDCTL_COPR_SENDMSG;
extern unsigned IOCTL_SNDCTL_COPR_WCODE;
extern unsigned IOCTL_SNDCTL_COPR_WDATA;
extern unsigned IOCTL_TCFLSH;
extern unsigned IOCTL_TCGETA;
extern unsigned IOCTL_TCGETS;
extern unsigned IOCTL_TCSBRK;
extern unsigned IOCTL_TCSBRKP;
extern unsigned IOCTL_TCSETA;
extern unsigned IOCTL_TCSETAF;
extern unsigned IOCTL_TCSETAW;
extern unsigned IOCTL_TCSETS;
extern unsigned IOCTL_TCSETSF;
extern unsigned IOCTL_TCSETSW;
extern unsigned IOCTL_TCXONC;
extern unsigned IOCTL_TIOCGLCKTRMIOS;
extern unsigned IOCTL_TIOCGSOFTCAR;
extern unsigned IOCTL_TIOCINQ;
extern unsigned IOCTL_TIOCLINUX;
extern unsigned IOCTL_TIOCSERCONFIG;
extern unsigned IOCTL_TIOCSERGETLSR;
extern unsigned IOCTL_TIOCSERGWILD;
extern unsigned IOCTL_TIOCSERSWILD;
extern unsigned IOCTL_TIOCSLCKTRMIOS;
extern unsigned IOCTL_TIOCSSOFTCAR;
extern unsigned IOCTL_VT_DISALLOCATE;
extern unsigned IOCTL_VT_GETSTATE;
extern unsigned IOCTL_VT_RESIZE;
extern unsigned IOCTL_VT_RESIZEX;
extern unsigned IOCTL_VT_SENDSIG;
extern unsigned IOCTL_MTIOCGET;
extern unsigned IOCTL_MTIOCTOP;
extern unsigned IOCTL_SIOCADDRT;
extern unsigned IOCTL_SIOCDELRT;
extern unsigned IOCTL_SNDCTL_DSP_GETBLKSIZE;
extern unsigned IOCTL_SNDCTL_DSP_GETFMTS;
extern unsigned IOCTL_SNDCTL_DSP_NONBLOCK;
extern unsigned IOCTL_SNDCTL_DSP_POST;
extern unsigned IOCTL_SNDCTL_DSP_RESET;
extern unsigned IOCTL_SNDCTL_DSP_SETFMT;
extern unsigned IOCTL_SNDCTL_DSP_SETFRAGMENT;
extern unsigned IOCTL_SNDCTL_DSP_SPEED;
extern unsigned IOCTL_SNDCTL_DSP_STEREO;
extern unsigned IOCTL_SNDCTL_DSP_SUBDIVIDE;
extern unsigned IOCTL_SNDCTL_DSP_SYNC;
extern unsigned IOCTL_SNDCTL_FM_4OP_ENABLE;
extern unsigned IOCTL_SNDCTL_FM_LOAD_INSTR;
extern unsigned IOCTL_SNDCTL_MIDI_INFO;
extern unsigned IOCTL_SNDCTL_MIDI_PRETIME;
extern unsigned IOCTL_SNDCTL_SEQ_CTRLRATE;
extern unsigned IOCTL_SNDCTL_SEQ_GETINCOUNT;
extern unsigned IOCTL_SNDCTL_SEQ_GETOUTCOUNT;
extern unsigned IOCTL_SNDCTL_SEQ_NRMIDIS;
extern unsigned IOCTL_SNDCTL_SEQ_NRSYNTHS;
extern unsigned IOCTL_SNDCTL_SEQ_OUTOFBAND;
extern unsigned IOCTL_SNDCTL_SEQ_PANIC;
extern unsigned IOCTL_SNDCTL_SEQ_PERCMODE;
extern unsigned IOCTL_SNDCTL_SEQ_RESET;
extern unsigned IOCTL_SNDCTL_SEQ_RESETSAMPLES;
extern unsigned IOCTL_SNDCTL_SEQ_SYNC;
extern unsigned IOCTL_SNDCTL_SEQ_TESTMIDI;
extern unsigned IOCTL_SNDCTL_SEQ_THRESHOLD;
extern unsigned IOCTL_SNDCTL_SYNTH_INFO;
extern unsigned IOCTL_SNDCTL_SYNTH_MEMAVL;
extern unsigned IOCTL_SNDCTL_TMR_CONTINUE;
extern unsigned IOCTL_SNDCTL_TMR_METRONOME;
extern unsigned IOCTL_SNDCTL_TMR_SELECT;
extern unsigned IOCTL_SNDCTL_TMR_SOURCE;
extern unsigned IOCTL_SNDCTL_TMR_START;
extern unsigned IOCTL_SNDCTL_TMR_STOP;
extern unsigned IOCTL_SNDCTL_TMR_TEMPO;
extern unsigned IOCTL_SNDCTL_TMR_TIMEBASE;
extern unsigned IOCTL_SOUND_MIXER_READ_ALTPCM;
extern unsigned IOCTL_SOUND_MIXER_READ_BASS;
extern unsigned IOCTL_SOUND_MIXER_READ_CAPS;
extern unsigned IOCTL_SOUND_MIXER_READ_CD;
extern unsigned IOCTL_SOUND_MIXER_READ_DEVMASK;
extern unsigned IOCTL_SOUND_MIXER_READ_ENHANCE;
extern unsigned IOCTL_SOUND_MIXER_READ_IGAIN;
extern unsigned IOCTL_SOUND_MIXER_READ_IMIX;
extern unsigned IOCTL_SOUND_MIXER_READ_LINE1;
extern unsigned IOCTL_SOUND_MIXER_READ_LINE2;
extern unsigned IOCTL_SOUND_MIXER_READ_LINE3;
extern unsigned IOCTL_SOUND_MIXER_READ_LINE;
extern unsigned IOCTL_SOUND_MIXER_READ_LOUD;
extern unsigned IOCTL_SOUND_MIXER_READ_MIC;
extern unsigned IOCTL_SOUND_MIXER_READ_MUTE;
extern unsigned IOCTL_SOUND_MIXER_READ_OGAIN;
extern unsigned IOCTL_SOUND_MIXER_READ_PCM;
extern unsigned IOCTL_SOUND_MIXER_READ_RECLEV;
extern unsigned IOCTL_SOUND_MIXER_READ_RECMASK;
extern unsigned IOCTL_SOUND_MIXER_READ_RECSRC;
extern unsigned IOCTL_SOUND_MIXER_READ_SPEAKER;
extern unsigned IOCTL_SOUND_MIXER_READ_STEREODEVS;
extern unsigned IOCTL_SOUND_MIXER_READ_SYNTH;
extern unsigned IOCTL_SOUND_MIXER_READ_TREBLE;
extern unsigned IOCTL_SOUND_MIXER_READ_VOLUME;
extern unsigned IOCTL_SOUND_MIXER_WRITE_ALTPCM;
extern unsigned IOCTL_SOUND_MIXER_WRITE_BASS;
extern unsigned IOCTL_SOUND_MIXER_WRITE_CD;
extern unsigned IOCTL_SOUND_MIXER_WRITE_ENHANCE;
extern unsigned IOCTL_SOUND_MIXER_WRITE_IGAIN;
extern unsigned IOCTL_SOUND_MIXER_WRITE_IMIX;
extern unsigned IOCTL_SOUND_MIXER_WRITE_LINE1;
extern unsigned IOCTL_SOUND_MIXER_WRITE_LINE2;
extern unsigned IOCTL_SOUND_MIXER_WRITE_LINE3;
extern unsigned IOCTL_SOUND_MIXER_WRITE_LINE;
extern unsigned IOCTL_SOUND_MIXER_WRITE_LOUD;
extern unsigned IOCTL_SOUND_MIXER_WRITE_MIC;
extern unsigned IOCTL_SOUND_MIXER_WRITE_MUTE;
extern unsigned IOCTL_SOUND_MIXER_WRITE_OGAIN;
extern unsigned IOCTL_SOUND_MIXER_WRITE_PCM;
extern unsigned IOCTL_SOUND_MIXER_WRITE_RECLEV;
extern unsigned IOCTL_SOUND_MIXER_WRITE_RECSRC;
extern unsigned IOCTL_SOUND_MIXER_WRITE_SPEAKER;
extern unsigned IOCTL_SOUND_MIXER_WRITE_SYNTH;
extern unsigned IOCTL_SOUND_MIXER_WRITE_TREBLE;
extern unsigned IOCTL_SOUND_MIXER_WRITE_VOLUME;
extern unsigned IOCTL_SOUND_PCM_READ_BITS;
extern unsigned IOCTL_SOUND_PCM_READ_CHANNELS;
extern unsigned IOCTL_SOUND_PCM_READ_FILTER;
extern unsigned IOCTL_SOUND_PCM_READ_RATE;
extern unsigned IOCTL_SOUND_PCM_WRITE_CHANNELS;
extern unsigned IOCTL_SOUND_PCM_WRITE_FILTER;
extern unsigned IOCTL_VT_ACTIVATE;
extern unsigned IOCTL_VT_GETMODE;
extern unsigned IOCTL_VT_OPENQRY;
extern unsigned IOCTL_VT_RELDISP;
extern unsigned IOCTL_VT_SETMODE;
extern unsigned IOCTL_VT_WAITACTIVE;
extern unsigned IOCTL_EQL_EMANCIPATE;
extern unsigned IOCTL_EQL_ENSLAVE;
extern unsigned IOCTL_EQL_GETMASTRCFG;
extern unsigned IOCTL_EQL_GETSLAVECFG;
extern unsigned IOCTL_EQL_SETMASTRCFG;
extern unsigned IOCTL_EQL_SETSLAVECFG;
extern unsigned IOCTL_EVIOCGKEYCODE_V2;
extern unsigned IOCTL_EVIOCGPROP;
extern unsigned IOCTL_EVIOCSKEYCODE_V2;
extern unsigned IOCTL_FS_IOC_GETFLAGS;
extern unsigned IOCTL_FS_IOC_GETVERSION;
extern unsigned IOCTL_FS_IOC_SETFLAGS;
extern unsigned IOCTL_FS_IOC_SETVERSION;
extern unsigned IOCTL_GIO_CMAP;
extern unsigned IOCTL_GIO_FONT;
extern unsigned IOCTL_GIO_UNIMAP;
extern unsigned IOCTL_GIO_UNISCRNMAP;
extern unsigned IOCTL_KDADDIO;
extern unsigned IOCTL_KDDELIO;
extern unsigned IOCTL_KDGETKEYCODE;
extern unsigned IOCTL_KDGKBDIACR;
extern unsigned IOCTL_KDGKBENT;
extern unsigned IOCTL_KDGKBLED;
extern unsigned IOCTL_KDGKBMETA;
extern unsigned IOCTL_KDGKBSENT;
extern unsigned IOCTL_KDMAPDISP;
extern unsigned IOCTL_KDSETKEYCODE;
extern unsigned IOCTL_KDSIGACCEPT;
extern unsigned IOCTL_KDSKBDIACR;
extern unsigned IOCTL_KDSKBENT;
extern unsigned IOCTL_KDSKBLED;
extern unsigned IOCTL_KDSKBMETA;
extern unsigned IOCTL_KDSKBSENT;
extern unsigned IOCTL_KDUNMAPDISP;
extern unsigned IOCTL_LPABORT;
extern unsigned IOCTL_LPABORTOPEN;
extern unsigned IOCTL_LPCAREFUL;
extern unsigned IOCTL_LPCHAR;
extern unsigned IOCTL_LPGETIRQ;
extern unsigned IOCTL_LPGETSTATUS;
extern unsigned IOCTL_LPRESET;
extern unsigned IOCTL_LPSETIRQ;
extern unsigned IOCTL_LPTIME;
extern unsigned IOCTL_LPWAIT;
extern unsigned IOCTL_MTIOCGETCONFIG;
extern unsigned IOCTL_MTIOCSETCONFIG;
extern unsigned IOCTL_PIO_CMAP;
extern unsigned IOCTL_PIO_FONT;
extern unsigned IOCTL_PIO_UNIMAP;
extern unsigned IOCTL_PIO_UNIMAPCLR;
extern unsigned IOCTL_PIO_UNISCRNMAP;
extern unsigned IOCTL_SCSI_IOCTL_GET_IDLUN;
extern unsigned IOCTL_SCSI_IOCTL_PROBE_HOST;
extern unsigned IOCTL_SCSI_IOCTL_TAGGED_DISABLE;
extern unsigned IOCTL_SCSI_IOCTL_TAGGED_ENABLE;
extern unsigned IOCTL_SIOCAIPXITFCRT;
extern unsigned IOCTL_SIOCAIPXPRISLT;
extern unsigned IOCTL_SIOCAX25ADDUID;
extern unsigned IOCTL_SIOCAX25DELUID;
extern unsigned IOCTL_SIOCAX25GETPARMS;
extern unsigned IOCTL_SIOCAX25GETUID;
extern unsigned IOCTL_SIOCAX25NOUID;
extern unsigned IOCTL_SIOCAX25SETPARMS;
extern unsigned IOCTL_SIOCDEVPLIP;
extern unsigned IOCTL_SIOCIPXCFGDATA;
extern unsigned IOCTL_SIOCNRDECOBS;
extern unsigned IOCTL_SIOCNRGETPARMS;
extern unsigned IOCTL_SIOCNRRTCTL;
extern unsigned IOCTL_SIOCNRSETPARMS;
extern unsigned IOCTL_SNDCTL_DSP_GETISPACE;
extern unsigned IOCTL_SNDCTL_DSP_GETOSPACE;
extern unsigned IOCTL_TIOCGSERIAL;
extern unsigned IOCTL_TIOCSERGETMULTI;
extern unsigned IOCTL_TIOCSERSETMULTI;
extern unsigned IOCTL_TIOCSSERIAL;
extern unsigned IOCTL_GIO_SCRNMAP;
extern unsigned IOCTL_KDDISABIO;
extern unsigned IOCTL_KDENABIO;
extern unsigned IOCTL_KDGETLED;
extern unsigned IOCTL_KDGETMODE;
extern unsigned IOCTL_KDGKBMODE;
extern unsigned IOCTL_KDGKBTYPE;
extern unsigned IOCTL_KDMKTONE;
extern unsigned IOCTL_KDSETLED;
extern unsigned IOCTL_KDSETMODE;
extern unsigned IOCTL_KDSKBMODE;
extern unsigned IOCTL_KIOCSOUND;
extern unsigned IOCTL_PIO_SCRNMAP;

extern const int si_SEGV_MAPERR;
extern const int si_SEGV_ACCERR;
}  // namespace __sanitizer

#  define CHECK_TYPE_SIZE(TYPE) \
    COMPILER_CHECK(sizeof(__sanitizer_##TYPE) == sizeof(TYPE))

#  define CHECK_SIZE_AND_OFFSET(CLASS, MEMBER)                      \
    COMPILER_CHECK(sizeof(((__sanitizer_##CLASS *)NULL)->MEMBER) == \
                   sizeof(((CLASS *)NULL)->MEMBER));                \
    COMPILER_CHECK(offsetof(__sanitizer_##CLASS, MEMBER) ==         \
                   offsetof(CLASS, MEMBER))

// For sigaction, which is a function and struct at the same time,
// and thus requires explicit "struct" in sizeof() expression.
#  define CHECK_STRUCT_SIZE_AND_OFFSET(CLASS, MEMBER)                      \
    COMPILER_CHECK(sizeof(((struct __sanitizer_##CLASS *)NULL)->MEMBER) == \
                   sizeof(((struct CLASS *)NULL)->MEMBER));                \
    COMPILER_CHECK(offsetof(struct __sanitizer_##CLASS, MEMBER) ==         \
                   offsetof(struct CLASS, MEMBER))

#  define SIGACTION_SYMNAME sigaction

typedef void *__sanitizer_timer_t;

#endif  // SANITIZER_WOS

#endif  // SANITIZER_PLATFORM_LIMITS_WOS_H
