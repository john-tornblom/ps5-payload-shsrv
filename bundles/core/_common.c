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

#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "_common.h"


/**
 * Convenient macros.
 **/
#define ispathsep(ch)   ((ch) == '/' || (ch) == '\\')
#define iseos(ch)       ((ch) == '\0')
#define ispathend(ch)   (ispathsep(ch) || iseos(ch))


/**
 * A sequence of commands.
 **/
typedef struct command_seq {
  const char         *name;
  main_t             *main;
  struct command_seq *next;
} command_seq_t;


/**
 * Head of the command sequence.
 **/
static command_seq_t* g_head = 0;


void
command_define(const char *name, main_t *main) {
  command_seq_t* cs = malloc(sizeof(command_seq_t));
  cs->name = name;
  cs->main = main;
  cs->next = g_head;
  g_head = cs;
}


main_t*
command_find(const char *name) {
  for(command_seq_t* cs=g_head; cs; cs=cs->next) {
    if(!strcmp(name, cs->name)) {
      return cs->main;
    }
  }
  return 0;
}


char*
get_workdir(void) {
  return getenv("PWD");
}


char*
normpath(const char *in, char *buf, size_t bufsize) {
  char *pos[PATH_MAX];
  char **top = pos;
  char *head = buf;
  int isabs = ispathsep(*in);

  if(isabs && bufsize) {
    *buf++ = '/';
    bufsize--;
  }

  *top++ = buf;

  while(!iseos(*in)) {
    while(ispathsep(*in)) {
      ++in;
    }

    if(iseos(*in)) {
      break;
    }

    if(memcmp(in, ".", 1) == 0 && ispathend(in[1])) {
      ++in;
      continue;
    }

    if(memcmp(in, "..", 2) == 0 && ispathend(in[2])) {
      in += 2;

      if(top != pos + 1) {
	buf = *--top;

      } else if(isabs) {
	buf = top[-1];

      } else {
	strncpy(buf, "../", bufsize);
	buf += 3;
	bufsize -= 3;
      }

      continue;
    }

    if(top - pos >= PATH_MAX) {
      return NULL;
    }

    *top++ = buf;

    while(!ispathend(*in) && bufsize) {
      *buf++ = *in++;
      bufsize--;
    }

    if(ispathsep(*in) && bufsize) {
      *buf++ = '/';
      bufsize--;
    }
  }

  *buf = '\0';

  if(*head == '\0') {
    strcpy(head, "./");
  }

  return head;
}


char*
abspath(const char *relpath) {
  char buf[PATH_MAX];

  if(relpath[0] == '/') {
    strncpy(buf, relpath, sizeof(buf));
  } else {
    snprintf(buf, sizeof(buf), "%s/%s", get_workdir(), relpath);
  }

  char *ap = malloc(PATH_MAX);
  return normpath(buf, ap, PATH_MAX);
}


void
hexdump(void *data, size_t size) {

  for(int i=0; i<size; i+=16) {
    uint8_t *buf = (uint8_t*)data+i;
    int n = i + 16 <= size ? 16 : size % 16;

    printf("%08x  ", i);

    for(int j=0; j<n; j++) {
      printf("%02x ", buf[j]);
    }

    for(int j=n; j<16; j++) {
      printf("   ");
    }

    printf("| ");

    for(int j=0; j<n; j++) {
      if(isblank(buf[j])) {
	printf(" ");
 
      } else if(!isprint(buf[j])) {
	printf(".");
 
      } else {
	printf("%c", buf[j]);
      }
    }
    printf("\n");
  }
}
