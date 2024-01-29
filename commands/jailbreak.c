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
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

#include <ps5/kernel.h>


/**
 * Escape application sandbox.
 **/
int
main_jailbreak(int argc, char **argv) {
  char cwd[PATH_MAX];
  intptr_t vnode;

  if(!(vnode=kernel_get_root_vnode())) {
    fprintf(stderr, "Unable to obtain root vnode\n");
    return -1;
  }

  if(kernel_set_proc_rootdir(getpid(), vnode)) {
    fprintf(stderr, "Unable to update root vnode\n");
    return -1;
  }

  setenv("OLDPWD", getenv("PWD"), 1);
  if(!getcwd(cwd, sizeof(cwd))) {
    chdir("/");
    setenv("PWD", "/", 1);
  } else {
    setenv("PWD", cwd, 1);
  }

  return 0;
}
