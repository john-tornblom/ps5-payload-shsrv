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


#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#ifdef __PROSPERO__
#include <ps5/kernel.h>
#endif

#include "commands.h"
#include "shell.h"

#define SHELL_LINE_BUFSIZE 1024
#define SHELL_TOK_BUFSIZE  128
#define SHELL_ARG_DELIM    " \t\r\n\a"
#define SHELL_CMD_DELIM    "|;&"


typedef struct sce_version {
  unsigned long unknown1;
  char          str_version[0x1c];
  unsigned int  bin_version;
  unsigned long unknown2;
} sce_version_t;


int  sceKernelSetProcessName(const char*);
int  sceKernelGetSystemSwVersion(sce_version_t *);
int  sceKernelGetProsperoSystemSwVersion(sce_version_t *);
int  sceKernelGetHwModelName(char *);
int  sceKernelGetHwSerialNumber(char *);
long sceKernelGetCpuFrequency(void);
int  sceKernelGetCpuTemperature(int *);
int  sceKernelGetSocSensorTemperature(int, int *);


/**
 * Callback function for main function of commands.
 **/
typedef int (main_t)(int argc, char **argv);


/**
 * Map names of commands to function entry points.
 **/
typedef struct shell_command {
  const char *name;
  main_t *main;
  int fork;
} shell_command_t;


static int main_help(int argc, char **argv);


shell_command_t commands[] = {
  {"cat", main_cat, 1},
  {"cd", main_cd, 0},
  {"chgrp", main_chgrp, 1},
  {"chmod", main_chmod, 1},
  {"chown", main_chown, 1},
  {"chroot", main_chroot, 0},
  {"cmp", main_cmp, 1},
  {"cp", main_cp, 1},
  {"echo", main_echo, 1},
  {"env", main_env, 0},
  {"exec", main_exec, 0},
  {"exit", main_exit, 0},
  {"file", main_file, 1},
  {"find", main_find, 1},
  {"grep", main_grep, 1},
  {"help", main_help, 1},
  {"hexdump", main_hexdump, 1},
  {"id", main_id, 1},
  {"jailbreak", main_jailbreak, 0},
  {"kill", main_kill, 1},
  {"ln", main_ln, 1},
  {"ls", main_ls, 1},
  {"mkdir", main_mkdir, 1},
  {"mknod", main_mknod, 1},
  {"mount", main_mount, 1},
  {"mv", main_mv, 1},
  {"notify", main_notify, 1},
  {"ps", main_ps, 1},
  {"pwd", main_pwd, 1},
  {"rm", main_rm, 1},
  {"rmdir", main_rmdir, 1},
  //{"self2elf", main_self2elf, 1},
  {"setegid", main_setegid, 0},
  {"seteuid", main_seteuid, 0},
  {"setgid", main_setgid, 0},
  {"setuid", main_setuid, 0},
  {"sfocreate", main_sfocreate, 1},
  {"sfoinfo", main_sfoinfo, 1},
  {"sleep", main_sleep, 1},
  {"stat", main_stat, 1},
  {"sum", main_sum, 1},
  {"sync", main_sync, 1},
  {"sysctl", main_sysctl, 1},
  {"touch", main_touch, 1},
  {"umount", main_umount, 1},
};



#define NB_SHELL_COMMANDS (sizeof(commands)/sizeof(shell_command_t))



/**
 * Read a line from stdin.
 **/
static char*
shell_readline(void) {
  int bufsize = SHELL_LINE_BUFSIZE;
  int position = 0;
  char *buffer_backup;
  char *buffer = calloc(bufsize, sizeof(char));
  char c;

  if(!buffer) {
    perror("calloc");
    return NULL;
  }

  while(1) {
    int len = read(STDIN_FILENO, &c, 1);
    if(len == -1 && errno == EINTR) {
      continue;
    }

    if(len <= 0) {
      free(buffer);
      return NULL;
    }

    if(c == '\n') {
      buffer[position] = '\0';
      return buffer;
    }

    buffer[position++] = c;

    if(position >= bufsize) {
      bufsize += SHELL_LINE_BUFSIZE;
      buffer_backup = buffer;
      buffer = realloc(buffer, bufsize);
      if(!buffer) {
	perror("realloc");
	free(buffer_backup);
	return NULL;
      }
    }
  }
}


/**
 * Split a string into an array of substrings seperated by 
 * a delimiter.
 **/
static char**
shell_splitstring(char *line, char *delim) {
  int bufsize = SHELL_TOK_BUFSIZE;
  int position = 0;
  char **tokens = calloc(bufsize, sizeof(char));
  char *token, **tokens_backup;
  char *state = 0;
  
  if(!tokens) {
    perror("calloc");
    return NULL;
  }

  token = strtok_r(line, delim, &state);
  while(token != NULL) {
    tokens[position] = token;
    position++;

    if(position >= bufsize) {
      bufsize += SHELL_TOK_BUFSIZE;
      tokens_backup = tokens;
      tokens = realloc(tokens, bufsize * sizeof(char*));
      if(!tokens) {
	perror("realloc");
	free(tokens_backup);
	return NULL;
      }
    }
    
    token = strtok_r(NULL, delim, &state);
  }

  tokens[position] = NULL;
  return tokens;
}


/**
 *
 **/
static void
shell_greet(void) {
  sce_version_t v;
  char s[1000];
  int temp = 0;

  printf("\n");
  printf("Welcome to shsrv.elf running on pid %d, ", getpid());
  printf("compiled %s at %s\n\n", __DATE__, __TIME__);

  s[0] = '\0';
  if(sceKernelGetHwModelName(s)) {
    perror("sceKernelGetHwModelName");
  } else {
    printf("Model:   %20s\n", s);
  }

  if(sceKernelGetHwSerialNumber(s)) {
    perror("sceKernelGetHwSerialNumber");
  } else {
    printf("S/N:     %20s\n", s);
  }
  
  if(sceKernelGetProsperoSystemSwVersion(&v)) {
    perror("sceKernelGetSystemSwVersion");
  } else {
    printf("S/W:     %20s\n", v.str_version);
  }
  
  if(sceKernelGetSocSensorTemperature(0, &temp)) {
    perror("sceKernelGetSocSensorTemperature");
  } else {
    printf("SoC temp:               %d °C\n", temp);
  }

  if(sceKernelGetCpuTemperature(&temp)) {
    perror("sceKernelGetCpuTemperature");
  } else {
    printf("CPU temp:               %d °C\n", temp);
  }

  printf("CPU freq:            %4ld MHz\n",
	 sceKernelGetCpuFrequency() / (1000*1000));
  
  printf("\nType 'help' for a list of commands\n");
  printf("\n");
}


/**
 * Print the shell prompt to stdout.
 **/
static void
shell_prompt(void) {
  char buf[PATH_MAX];
  char *cwd;

  if(!(cwd = getenv("PWD"))) {
    cwd = getcwd(buf, sizeof(buf));
  }
  
  fprintf(stdout, "%s$ ", cwd ? cwd : "(null)");
  fflush(stdout);
}


/**
 * Fork the execution of a command.
 **/
static int
shell_fork(main_t *main, int argc, char **argv) {
  pid_t pid = syscall(SYS_fork);
  if (pid == 0) {
    sceKernelSetProcessName(argv[0]);
    int rc = main(argc, argv);
    _exit(rc);
    return rc;
    
  } else if (pid < 0) {
    perror("fork");
    return -1;
    
  } else {
    int status = 0;
    do {
      waitpid(pid, &status, WUNTRACED);
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    if(WIFEXITED(status)) {
      return WEXITSTATUS(status);
    } else {
      return EXIT_FAILURE;
    }
  }
}


/**
 * Execute a shell command.
 **/
static int
shell_execute(char **argv) {
  int argc = 0;

  while(argv[argc]) {
    argc++;
  }
  
  if(!argc) {
    return -1;
  }

  for(int i=0; i<NB_SHELL_COMMANDS; i++) {
    if(strcmp(argv[0], commands[i].name)) {
      continue;
    }
    
    if(commands[i].fork) {
      return shell_fork(commands[i].main, argc, argv);
    } else {
      return commands[i].main(argc, argv);
    }
  }
  
  printf("%s: command not found\n", argv[0]);
  return -1;
}


/**
 * Shell entry point.
 **/
void
shell_loop(void) {
  char *line = NULL;
  char **cmds = NULL;
  char **args = NULL;
  int pipefd[2] = {0, 0};
  int running = 1;
  int infd = 0;
  int outfd = 1;

  sceKernelSetProcessName("sh");
  setenv("HOME", "/", 0);
  setenv("PWD", "/", 0);
  shell_greet();

  while(running) {
    shell_prompt();
    
    line = shell_readline();
    if(!(cmds = shell_splitstring(line, SHELL_CMD_DELIM))) {
      free(line);
      continue;
    }

    infd = dup(0);
    outfd = dup(1);

    for(int i=0; cmds[i]; i++) {
      if(!(args = shell_splitstring(cmds[i], SHELL_ARG_DELIM))) {
	continue;
      }

      if(cmds[i+1] && !pipe(pipefd)) {
	dup2(pipefd[1], 1);
	close(pipefd[1]);
      } else {
	dup2(outfd, 1);
      }

      shell_execute(args);

      if(cmds[i+1]) {
	dup2(pipefd[0], 0);
	close(pipefd[0]);
      } else {
	dup2(infd, 0);
      }

      fflush(NULL);
      free(args);
    }
    free(line);
    free(cmds);

    close(infd);
    close(outfd);
  }
}


/**
 * Print a list of available commands to stdout.
 **/
static int
main_help(int argc, char **argv) {
  printf("Available commands are:\n");
  for(int i=0; i<NB_SHELL_COMMANDS; i++) {
    printf("  %s\n", commands[i].name);
  }
  
  return 0;
}

