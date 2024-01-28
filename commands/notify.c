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
#include <string.h>


typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;


void sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
 

/**
 * 
 **/
int
main_notify(int argc, char **argv) {
  notify_request_t req;
  
  bzero(&req, sizeof req);
  if(argc > 1) {
    strncpy(req.message, argv[1], sizeof req.message);
  }
  
#ifdef __PROSPERO__
  sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
#else
  printf("%s\n", req.message);
#endif

  return 0;
}

