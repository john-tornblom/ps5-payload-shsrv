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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>


int
main_setegid(int argc, char **argv) {
  if(argc <= 1) {
    printf("%s: missing operand\n", argv[0]);
    return EXIT_FAILURE;
  }
  
  if(syscall(SYS_setegid, atoi(argv[1]))) {
    perror(argv[0]);
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}



