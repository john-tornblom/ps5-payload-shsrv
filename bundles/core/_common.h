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

#pragma once

#include <stdint.h>
#include <stdlib.h>


/**
 * Prototype for main functions.
 **/
typedef int (main_t)(int argc, char **argv);



/**
 * Insert a command at the head of the sequence.
 **/
void command_define(const char *name, main_t *main);


/**
 * Find the command with a given name.
 **/
main_t* command_find(const char *name);


/**
 * Return the current working directory of the calling process.
 **/
char* get_workdir(void);


/**
 * Normalize a path.
 **/
char* normpath(const char *path, char *buf, size_t bufsize);


/**
 * Return an absolute path.
 **/
char* abspath(const char *relpath);


/**
 * Dump a memory region to stdout.
 **/
void hexdump(void *data, size_t size);
