/* Copyright (C) 2024 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define MAX_MESSAGE_SIZE    0x2000
#define MAX_STACK_FRAMES    64


typedef struct callframe {
  void *sp;
  void *pc;
} callframe_t;


typedef struct vmem_query_info {
  void* unk01;
  void* unk02;
  off_t offset;
  int unk04;
  int unk05;
  unsigned isFlexibleMemory : 1;
  unsigned isDirectMemory : 1;
  unsigned isStack : 1;
  unsigned isPooledMemory : 1;
  unsigned isCommitted : 1;
  char name[32];
} vmem_query_info;


int sceKernelBacktraceSelf(callframe_t*, size_t, uint32_t*, int);
int sceKernelVirtualQuery(const void *, int, vmem_query_info*, size_t);
int sceKernelDebugOutText(int, const char*, ...);


/**
 * Log a backtrace to stderr.
 **/
void
crashlog_backtrace(const char* reason) {
  char addr2line[MAX_STACK_FRAMES * 20];
  callframe_t frames[MAX_STACK_FRAMES];
  char buf[MAX_MESSAGE_SIZE + 3];
  unsigned int nb_frames = 0;
  vmem_query_info info;
  char temp[80];

  memset(addr2line, 0, sizeof addr2line);
  memset(frames, 0, sizeof frames);
  memset(buf, 0, sizeof buf);

  snprintf(buf, sizeof buf, "%s\n", reason);

  strncat(buf, " Backtrace:\n", MAX_MESSAGE_SIZE);
  sceKernelBacktraceSelf(frames, sizeof frames, &nb_frames, 0);
  for(unsigned int i=0; i<nb_frames; i++) {
    memset(&info, 0, sizeof info);
    sceKernelVirtualQuery(frames[i].pc, 0, &info, sizeof info);

    snprintf(temp, sizeof temp,
	     "   #%02d %32s: 0x%lx\n",
	     i + 1, info.name, frames[i].pc - info.unk01 - 1);
    strncat(buf, temp, MAX_MESSAGE_SIZE);

    snprintf(temp, sizeof temp,
	     "0x%lx ", frames[i].pc - info.unk01 - 1);
    strncat(addr2line, temp, sizeof addr2line - 1);
  }

  strncat(buf, " addr2line: ", MAX_MESSAGE_SIZE);
  strncat(buf, addr2line, MAX_MESSAGE_SIZE);
  strncat(buf, "\n", MAX_MESSAGE_SIZE);

  buf[MAX_MESSAGE_SIZE+1] = '\n';
  buf[MAX_MESSAGE_SIZE+2] = '\0';

  fprintf(stderr, "%s", buf);
}
