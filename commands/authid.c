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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ps5/kernel.h>


/**
 *
 **/
int
main_authid(int argc, char **argv) {
  uint64_t authid;
  pid_t pid = getpid();
  
  if(argc < 2) {
    printf("0x%lx\n", kernel_get_ucred_authid(pid));
    return 0;
  }

  if(sscanf(argv[1], "0x%lx", &authid) != 1) {
    return -1;
  }

  return kernel_set_ucred_authid(pid, authid);
}


