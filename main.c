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


#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include "shell.h"


/**
 * 
 **/
static void
spawn_shell(int srvfd, int fd) {
  if(syscall(SYS_fork)) {
    return;
  }

  syscall(SYS_thr_set_name, -1, "sh");

  close(srvfd);
  close(STDERR_FILENO);
  close(STDOUT_FILENO);
  close(STDIN_FILENO);

  dup2(fd, STDIN_FILENO);
  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);
  close(fd);

  shell_loop();
  _exit(0);
}


/**
 *
 **/
static int
serve_shell(uint16_t port) {
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  char ip[INET_ADDRSTRLEN];
  struct ifaddrs *ifaddr;
  int ifaddr_wait = 1;
  socklen_t addr_len;
  int connfd;
  int srvfd;

  if(getifaddrs(&ifaddr) == -1) {
    perror("[shsrv.elf] getifaddrs");
    _exit(EXIT_FAILURE);
  }

  // Enumerate all AF_INET IPs
  for(struct ifaddrs *ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) {
      continue;
    }

    if(ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    // skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }
    ifaddr_wait = 0;
    printf("[shsrv.elf] Serving shell on %s:%d (%s)", ip, port, ifa->ifa_name);
  }

  freeifaddrs(ifaddr);

  if(ifaddr_wait) {
    return 0;
  }

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("[shsrv.elf] socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    perror("[shsrv.elf] setsockopt");
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
    perror("[shsrv.elf] bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    perror("[shsrv.elf] listen");
    return -1;
  }

  while(1) {
    addr_len = sizeof(client_addr);
    if((connfd=accept(srvfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
      perror("[shsrv.elf] accept");
      break;
    }
    spawn_shell(srvfd, connfd);
    close(connfd);
  }

  return close(srvfd);
}


/**
 * Get the pid of a process with the given name.
 **/
static pid_t
find_pid(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    perror("[shsrv.elf] sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    perror("[shsrv.elf] malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    perror("[shsrv.elf] sysctl");
    return -1;
  }

  for(uint8_t *ptr=buf; ptr<(buf+buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname)) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}


static void
init_stdio(void) {
  int fd = open("/dev/console", O_WRONLY);

  close(STDERR_FILENO);
  close(STDOUT_FILENO);

  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);

  close(fd);
}


int
main(void) {
  const int port = 2323;
  pid_t pid;

  signal(SIGCHLD, SIG_IGN);
  if(syscall(SYS_rfork, RFPROC | RFNOWAIT | RFFDG)) {
    return 0;
  }

  while((pid=find_pid("shsrv.elf")) > 0) {
    if(kill(pid, SIGTERM)) {
      perror("[shsrv.elf] kill");
    }
    sleep(1);
  }

  syscall(SYS_thr_set_name, -1, "shsrv.elf");
  syscall(SYS_setsid);
  signal(SIGCHLD, SIG_IGN);
  init_stdio();

  printf("[shsrv.elf] Launching shell server compiled %s at %s\n",
	 __DATE__, __TIME__);
  while(1) {
    serve_shell(port);
    sleep(3);
  }

  return 0;
}

