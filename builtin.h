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

#pragma once

#include <stdint.h>


/**
 * Prototype for builtin commands.
 **/
typedef int (builtin_cmd_t)(int argc, char **argv);


/**
 * Find a builtin command by its name.
 **/
builtin_cmd_t* builtin_find_cmd(const char* name);


/**
 * Find a builtin ELF by its name.
 **/
uint8_t* builtin_find_elf(const char* name);
