/* Copyright (C) 2021 John Törnblom

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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "_common.h"


int
main_chroot(int argc, char **argv) {
  if(argc <= 1) {
    fprintf(stderr, "%s: missing operand\n", argv[0]);
    return -1;
  }

  char *path = abspath(argv[1]);
  int rc = EXIT_SUCCESS;
  pid_t pid = getpid();
  uint64_t authid = kernel_get_ucred_authid(pid);
  
  kernel_set_ucred_authid(pid, 0x4800000000000007l);
  rc = chroot(path);
  kernel_set_ucred_authid(pid, authid);

  free(path);
  
  if(rc) {
    perror(argv[1]);
    return -1;
  }

  return 0;
}

