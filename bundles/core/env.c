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

#include "_common.h"


extern char **environ;


/**
 *
 **/
static int
env_main(int argc, char **argv) {
  char **var;

  if(!environ) {
    return 0;
  }
  
  for(var=environ; *var; var++) {
    fprintf(stdout, "%s\n", *var);
  }
  
  return 0;
}


/**
 *
 **/
__attribute__((constructor)) static void
env_constructor(void) {
  command_define("env", env_main);
}
