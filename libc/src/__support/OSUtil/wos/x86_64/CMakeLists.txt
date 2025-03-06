add_header_library(
  wos_x86_64_util
  HDRS
    syscall.h
  DEPENDS
    libc.src.__support.common
)
