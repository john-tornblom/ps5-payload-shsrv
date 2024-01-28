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
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <unistd.h>


#include <ps5/kernel.h>


#include "shell.h"


/**
 * Data structure used to send UI notifications on the PS5.
 **/
typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;


int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
int sceKernelSetProcessName(const char*);


static int
init_client(int fd) {
  for(int i=0; i<1024; i++) {
    if(i != fd && fcntl(i, F_GETFD) > 0 && errno != EBADF) {
      close(i);
    }
  }
  
  if(dup2(fd, STDIN_FILENO) < 0) {
    return -1;
  }
    
  if(dup2(fd, STDOUT_FILENO) < 0) {
    return -1;
  }
  
  if(dup2(fd, STDERR_FILENO) < 0) {
    return -1;
  }

  close(fd);
  return 0;
}


/**
 * 
 **/
static void
spawn_client(int master, int slave) {
  pid_t pid = syscall(SYS_fork);
  
  if (pid == 0) {
    close(master);
    if(init_client(slave)) {
      _exit(errno);
    } else {
      shell_loop();
    }
    _exit(0);
  }

  close(slave);
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
  notify_request_t req;
  int ifaddr_wait = 1;
  socklen_t addr_len;
  int connfd;
  int srvfd;

  if(getifaddrs(&ifaddr) == -1) {
    perror("[shsrv.elf] getifaddrs");
    _exit(EXIT_FAILURE);
  }

  signal(SIGPIPE, SIG_IGN);

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
    // skip interfaces without an IP
    if(!strncmp("0.", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }

    bzero(&req, sizeof(req));
    sprintf(req.message, "Serving shell on %s:%d (%s)", ip, port, ifa->ifa_name);
    printf("[shsrv.elf] %s\n", req.message);
    ifaddr_wait = 0;

#ifdef __PROSPERO__
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
#endif
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

  addr_len = sizeof(client_addr);

  while(1) {
    if((connfd=accept(srvfd, (struct sockaddr*)&client_addr, &addr_len)) < 0) {
      perror("[shsrv.elf] accept");
      break;
    }

    spawn_client(srvfd, connfd);
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
    perror("sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    perror("malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    perror("sysctl");
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


int
main(void) {
  const int port = 2323;
  pid_t pid;

  if(syscall(SYS_rfork, RFPROC | RFNOWAIT | RFFDG)) {
    return 0;
  }

  open("/dev/null", O_RDONLY);    // stdin
  open("/dev/console", O_WRONLY); // stdout
  open("/dev/console", O_WRONLY); // stderr

  if((pid=find_pid("shsrv.elf")) > 0) {
    kill(pid, SIGKILL);
    sleep(1);
  }
  sceKernelSetProcessName("shsrv.elf");

  while(1) {
    serve_shell(port);
    sleep(3);
  }

  return 0;
}

