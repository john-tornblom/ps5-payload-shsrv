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

#include <string.h>

#include "commands/env_elf.c"
#include "commands/ls_elf.c"
#include "commands/ps_elf.c"

/**
 * Map names of bundled commands.
 **/
typedef struct bundle_map {
  const char    *name;
  unsigned char *elf;
} bundle_map_t;


static bundle_map_t map[] = {
  {"env", env_elf},
  {"ls", ls_elf},
  {"ps", ps_elf},
};


unsigned char*
bundle_find_elf(const char* name) {
  for(int i=0; i<sizeof(map)/sizeof(map[0]); i++) {
    if(!strcmp(name, map[i].name)) {
      return map[i].elf;
    }
  }

  return 0;
}
