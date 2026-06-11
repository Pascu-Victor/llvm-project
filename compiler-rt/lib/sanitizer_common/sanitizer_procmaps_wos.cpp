//===-- sanitizer_procmaps_wos.cpp ----------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Information about the process mappings (WOS parts).
//===----------------------------------------------------------------------===//

#include "sanitizer_platform.h"
#if SANITIZER_WOS
#  include "sanitizer_common.h"
#  include "sanitizer_procmaps.h"
#  include "sanitizer_wos.h"

namespace __sanitizer {

void ReadProcMaps(ProcSelfMapsBuff* proc_maps) {
  if (!ReadFileToBuffer("/proc/self/maps", &proc_maps->data,
                        &proc_maps->mmaped_size, &proc_maps->len)) {
    proc_maps->data = nullptr;
    proc_maps->mmaped_size = 0;
    proc_maps->len = 0;
  }
}

static bool IsOneOf(char c, char c1, char c2) { return c == c1 || c == c2; }

static bool Consume(char expected, const char** p, const char* end) {
  if (*p >= end || **p != expected)
    return false;
  (*p)++;
  return true;
}

static bool ParseHexBounded(const char** p, const char* end, uptr* value) {
  if (*p >= end || !IsHex(**p))
    return false;
  uptr result = 0;
  while (*p < end && IsHex(**p)) {
    char c = **p;
    result *= 16;
    if (c >= '0' && c <= '9')
      result += c - '0';
    else if (c >= 'a' && c <= 'f')
      result += c - 'a' + 10;
    else
      result += c - 'A' + 10;
    (*p)++;
  }
  *value = result;
  return true;
}

bool MemoryMappingLayout::Next(MemoryMappedSegment* segment) {
  if (Error())
    return false;  // simulate empty maps

  const char* last = data_.proc_self_maps.data + data_.proc_self_maps.len;
  while (data_.current < last) {
    const char* line = data_.current;
    const char* next_line =
        (const char*)internal_memchr(line, '\n', last - line);
    if (next_line == 0)
      next_line = last;
    data_.current = next_line < last ? next_line + 1 : next_line;

    const char* current = line;
    uptr start = 0;
    uptr end = 0;
    uptr offset = 0;
    uptr unused = 0;
    int protection = 0;

    // Example: 08048000-08056000 r-xp 00000000 03:0c 64593   /foo/bar
    if (!ParseHexBounded(&current, next_line, &start) ||
        !Consume('-', &current, next_line) ||
        !ParseHexBounded(&current, next_line, &end) ||
        !Consume(' ', &current, next_line))
      continue;

    if (current >= next_line || !IsOneOf(*current, '-', 'r'))
      continue;
    if (*current++ == 'r')
      protection |= kProtectionRead;
    if (current >= next_line || !IsOneOf(*current, '-', 'w'))
      continue;
    if (*current++ == 'w')
      protection |= kProtectionWrite;
    if (current >= next_line || !IsOneOf(*current, '-', 'x'))
      continue;
    if (*current++ == 'x')
      protection |= kProtectionExecute;
    if (current >= next_line || !IsOneOf(*current, 's', 'p'))
      continue;
    if (*current++ == 's')
      protection |= kProtectionShared;

    if (!Consume(' ', &current, next_line) ||
        !ParseHexBounded(&current, next_line, &offset) ||
        !Consume(' ', &current, next_line) ||
        !ParseHexBounded(&current, next_line, &unused) ||
        !Consume(':', &current, next_line) ||
        !ParseHexBounded(&current, next_line, &unused) ||
        !Consume(' ', &current, next_line))
      continue;

    while (current < next_line && IsDecimal(*current)) current++;
    while (current < next_line && *current == ' ') current++;

    segment->start = start;
    segment->end = end;
    segment->offset = offset;
    segment->protection = protection;
    if (segment->filename) {
      uptr len = Min((uptr)(next_line - current), segment->filename_size - 1);
      internal_strncpy(segment->filename, current, len);
      segment->filename[len] = 0;
    }
    return true;
  }

  return false;
}

}  // namespace __sanitizer

#endif  // SANITIZER_WOS
