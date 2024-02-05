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


/**
 *
 **/
int
main_export(int argc, char **argv) {
  char *name;
  char *val;
  char *sep;
  
  if(argc < 2 || !(sep=strstr(argv[1], "="))) {
    printf("usage: %s NAME=value\n", argv[0]);
    return -1;
  }

  name = argv[1];
  *sep = 0;
  val = sep+1;
  
  if(setenv(name, val, 1)) {
    perror(argv[0]);
    return -1;
  }
  
  return 0;
}


