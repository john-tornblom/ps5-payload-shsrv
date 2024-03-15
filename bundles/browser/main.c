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
#include <unistd.h>


int sceUserServiceInitialize(void*);
void sceUserServiceTerminate(void);

int sceSystemServiceLaunchWebBrowser(const char *uri);


int
main(int argc, char** argv) {
  if(argc < 2) {
    puts("usage: %s <URL>");
    return -1;
  }

  if(sceUserServiceInitialize(0)) {
    perror("sceUserServiceInitialize");
    return EXIT_FAILURE;
  }

  atexit(sceUserServiceTerminate);

  if(sceSystemServiceLaunchWebBrowser(argv[1])) {
    perror("sceSystemServiceLaunchWebBrowser");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

