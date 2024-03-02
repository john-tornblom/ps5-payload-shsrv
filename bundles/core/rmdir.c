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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>

#include "_common.h"


/**
 *
 **/
static int
rmdir_main(int argc, char **argv) {
  if(argc <= 1) {
    fprintf(stderr, "%s: missing operand\n", argv[0]);
    return -1;
  }

  for(int i=0; i<argc-1; i++) {
    char *path = abspath(argv[i+1]);

    if(rmdir(path)) {
      perror(path);
    }

    free(path);
  }

  return 0;
}


/**
 *
 **/
__attribute__((constructor)) static void
rmdir_constructor(void) {
  command_define("rmdir", rmdir_main);
}
