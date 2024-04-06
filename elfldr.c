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

#include <elf.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "elfldr.h"
#include "pt.h"


#ifndef IPV6_2292PKTOPTIONS
#define IPV6_2292PKTOPTIONS 25
#endif


/**
 * Convenient macros.
 **/
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))


/**
 * Context structure for the ELF loader.
 **/
typedef struct elfldr_ctx {
  uint8_t* elf;
  pid_t    pid;

  intptr_t base_addr;
  size_t   base_size;
} elfldr_ctx_t;


/**
 * Absolute path to the SceSpZeroConf eboot.
 **/
static const char* SceSpZeroConf = "/system/vsh/app/NPXS40112/eboot.bin";


/**
 *
 **/
int sceKernelSpawn(int *pid, int dbg, const char *path, char *root,
		   char* argv[]);


/**
 *
 **/
extern char** environ;


/**
* Parse a R_X86_64_RELATIVE relocatable.
**/
static int
r_relative(elfldr_ctx_t *ctx, Elf64_Rela* rela) {
  intptr_t loc = ctx->base_addr + rela->r_offset;
  intptr_t val = ctx->base_addr + rela->r_addend;

  return mdbg_copyin(ctx->pid, &val, loc, sizeof(val));
}


/**
 * Parse a PT_LOAD program header.
 **/
static int
pt_load(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  intptr_t addr = ctx->base_addr + phdr->p_vaddr;
  size_t memsz = ROUND_PG(phdr->p_memsz);

  if(!phdr->p_memsz) {
    return 0;
  }

  if((addr=pt_mmap(ctx->pid, addr, memsz, PROT_WRITE | PROT_READ,
		   MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
		   -1, 0)) == -1) {
    pt_perror(ctx->pid, "mmap");
    return -1;
  }

  if(!phdr->p_filesz) {
    return 0;
  }

  if(mdbg_copyin(ctx->pid, ctx->elf+phdr->p_offset, addr, phdr->p_filesz)) {
    pt_perror(ctx->pid, "mdbg_copyin");
    return -1;
  }

  return 0;
}


/**
 * Reload a PT_LOAD program header with executable permissions.
 **/
static int
pt_reload(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  intptr_t addr = ctx->base_addr + phdr->p_vaddr;
  size_t memsz = ROUND_PG(phdr->p_memsz);
  int prot = PFLAGS(phdr->p_flags);
  int alias_fd = -1;
  int shm_fd = -1;
  void* data = 0;
  int error = 0;

  if(!(data=mmap(0, memsz, PROT_READ | PROT_WRITE,
		 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0))) {
    perror("mmap");
    return -1;
  }

  // Backup data
  else if(mdbg_copyout(ctx->pid, addr, data, memsz)) {
    pt_perror(ctx->pid, "mdbg_copyout");
    error = -1;
  }

  // Create shm with executable permissions.
  else if((shm_fd=pt_jitshm_create(ctx->pid, 0, memsz,
				   prot | PROT_READ | PROT_WRITE)) < 0) {
    pt_perror(ctx->pid, "jitshm_create");
    error = -1;
  }

  // Map shm into an executable address space.
  else if((addr=pt_mmap(ctx->pid, addr, memsz, prot,
			MAP_FIXED | MAP_PRIVATE,
			shm_fd, 0)) == -1) {
    pt_perror(ctx->pid, "mmap");
    error = -1;
  }

  // Create an shm alias fd with write permissions.
  else if((alias_fd=pt_jitshm_alias(ctx->pid, shm_fd,
				    PROT_READ | PROT_WRITE)) < 0) {
    pt_perror(ctx->pid, "jitshm_alias");
    error = -1;
  }

  // Map shm alias into a writable address space.
  else if((addr=pt_mmap(ctx->pid, 0, memsz, PROT_READ | PROT_WRITE, MAP_SHARED,
			alias_fd, 0)) == -1) {
    pt_perror(ctx->pid, "mmap");
    error = -1;
  }

  // Resore data
  else {
    if(mdbg_copyin(ctx->pid, data, addr, memsz)) {
      pt_perror(ctx->pid, "mdbg_copyin");
      error = -1;
    }
    pt_msync(ctx->pid, addr, memsz, MS_SYNC);
    pt_munmap(ctx->pid, addr, memsz);
  }

  munmap(data, memsz);
  pt_close(ctx->pid, alias_fd);
  pt_close(ctx->pid, shm_fd);

  return error;
}


/**
 * Load an ELF into the address space of a process with the given pid.
 **/
static intptr_t
elfldr_load(pid_t pid, uint8_t *elf) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

  elfldr_ctx_t ctx = {.elf = elf, .pid=pid};

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  int error = 0;

  // Sanity check, we only support 64bit ELFs.
  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
     ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F') {
    puts("elfldr_load: Malformed ELF file");
    return 0;
  }

  // Compute size of virtual memory region.
  for(int i=0; i<ehdr->e_phnum; i++) {
    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  ctx.base_size = max_vaddr - min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int prot = PROT_READ | PROT_WRITE;
  if(ehdr->e_type == ET_DYN) {
    ctx.base_addr = 0;
  } else if(ehdr->e_type == ET_EXEC) {
    ctx.base_addr = min_vaddr;
    flags |= MAP_FIXED;
  } else {
    puts("elfldr_load: ELF type not supported");
    return 0;
  }

  // Reserve an address space of sufficient size.
  if((ctx.base_addr=pt_mmap(pid, ctx.base_addr, ctx.base_size, prot,
			    flags, -1, 0)) == -1) {
    pt_perror(pid, "pt_mmap");
    return 0;
  }

  // Parse program headers.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    switch(phdr[i].p_type) {
    case PT_LOAD:
      error = pt_load(&ctx, &phdr[i]);
      break;
    }
  }

  // Apply relocations.
  for(int i=0; i<ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela* rela = (Elf64_Rela*)(elf + shdr[i].sh_offset);
    for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela); j++) {
      switch(rela[j].r_info & 0xffffffffl) {
      case R_X86_64_RELATIVE:
	error = r_relative(&ctx, &rela[j]);
	break;
      }
    }
  }

  // Set protection bits on mapped segments.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_flags & PF_X) {
      error = pt_reload(&ctx, &phdr[i]);
    } else {
      if(pt_mprotect(pid, ctx.base_addr + phdr[i].p_vaddr,
		     ROUND_PG(phdr[i].p_memsz),
		     PFLAGS(phdr[i].p_flags))) {
	pt_perror(pid, "pt_mprotect");
	error = 1;
      }
    }
  }

  if(pt_msync(pid, ctx.base_addr, ctx.base_size, MS_SYNC)) {
    pt_perror(pid, "pt_msync");
    error = 1;
  }

  if(error) {
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    return 0;
  }

  return ctx.base_addr + ehdr->e_entry;
}


/**
 *
 **/
static intptr_t
elfldr_envp(pid_t pid) {
  size_t size = sizeof(char*);
  intptr_t envp = 0;
  intptr_t pos = 0;
  int n = 0;

  // no env variables defined
  if(!environ || !environ[0]) {
    return 0;
  }

  // compute needed memory size and number of variables
  while(environ[n]) {
    size += (8 + strlen(environ[n]) + 1);
    n++;
  }
  size = ROUND_PG(size);

  // allocate memory
  if((envp=pt_mmap(pid, 0, size, PROT_WRITE | PROT_READ,
		   MAP_ANONYMOUS | MAP_PRIVATE,
		   -1, 0)) == -1) {
    pt_perror(pid, "mmap");
    return 0;
  }

  // copy data
  pos = envp + ((n + 1) * 8);
  for(int i=0; i<n; i++) {
    size_t len = strlen(environ[i]) + 1;

    // copy string
    if(mdbg_copyin(pid, environ[i], pos, len)) {
      pt_perror(pid, "mdbg_copyin");
      pt_munmap(pid, envp, size);
      return 0;
    }

    // copy pointer to string 
    mdbg_setlong(pid, envp + (i*8), pos);
    pos += len;
  }

  // null-terminate envp
  mdbg_setlong(pid, envp + (n*8), 0);

  return envp;
}


/**
 * Create payload args in the address space of the process with the given pid.
 **/
static intptr_t
elfldr_payload_args(pid_t pid) {
  int victim_sock;
  int master_sock;
  intptr_t buf;
  int pipe0;
  int pipe1;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "pt_mmap");
    return 0;
  }

  if((master_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    pt_perror(pid, "pt_socket");
    return 0;
  }

  mdbg_setint(pid, buf+0x00, 20);
  mdbg_setint(pid, buf+0x04, IPPROTO_IPV6);
  mdbg_setint(pid, buf+0x08, IPV6_TCLASS);
  mdbg_setint(pid, buf+0x0c, 0);
  mdbg_setint(pid, buf+0x10, 0);
  mdbg_setint(pid, buf+0x14, 0);
  if(pt_setsockopt(pid, master_sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, 24)) {
    pt_perror(pid, "pt_setsockopt");
    return 0;
  }

  if((victim_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    pt_perror(pid, "pt_socket");
    return 0;
  }

  mdbg_setint(pid, buf+0x00, 0);
  mdbg_setint(pid, buf+0x04, 0);
  mdbg_setint(pid, buf+0x08, 0);
  mdbg_setint(pid, buf+0x0c, 0);
  mdbg_setint(pid, buf+0x10, 0);
  if(pt_setsockopt(pid, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20)) {
    pt_perror(pid, "pt_setsockopt");
    return 0;
  }

  if(kernel_overlap_sockets(pid, master_sock, victim_sock)) {
    puts("kernel_overlap_sockets failed");
    return 0;
  }

  if(pt_pipe(pid, buf)) {
    pt_perror(pid, "pt_pipe");
    return 0;
  }
  pipe0 = pt_getint(pid, buf);
  pipe1 = pt_getint(pid, buf+4);

  intptr_t args       = buf;
  intptr_t dlsym      = pt_resolve(pid, "LwG8g3niqwA");
  intptr_t rwpipe     = buf + 0x100;
  intptr_t rwpair     = buf + 0x200;
  intptr_t kpipe_addr = kernel_get_proc_file(pid, pipe0);
  intptr_t payloadout = buf + 0x300;

  mdbg_setlong(pid, args + 0x00, dlsym);
  mdbg_setlong(pid, args + 0x08, rwpipe);
  mdbg_setlong(pid, args + 0x10, rwpair);
  mdbg_setlong(pid, args + 0x18, kpipe_addr);
  mdbg_setlong(pid, args + 0x20, KERNEL_ADDRESS_DATA_BASE);
  mdbg_setlong(pid, args + 0x28, payloadout);
  mdbg_setint(pid, rwpipe + 0, pipe0);
  mdbg_setint(pid, rwpipe + 4, pipe1);
  mdbg_setint(pid, rwpair + 0, master_sock);
  mdbg_setint(pid, rwpair + 4, victim_sock);
  mdbg_setint(pid, payloadout, 0);

  return args;
}


/**
 * Prepare registers of a process for execution of an ELF.
 **/
static int
elfldr_prepare_exec(pid_t pid, uint8_t *elf) {
  uint8_t call_rax[] = {0xff, 0xd0};
  intptr_t entry;
  intptr_t args;
  struct reg r;

  if(pt_getregs(pid, &r)) {
    perror("pt_getregs");
    return -1;
  }

  if(!(entry=elfldr_load(pid, elf))) {
    puts("elfldr_load failed");
    return -1;
  }

  if(!(args=elfldr_payload_args(pid))) {
    puts("elfldr_payload_args failed");
    return -1;
  }

  if(mdbg_copyin(pid, call_rax, r.r_rip, sizeof(call_rax))) {
    perror("mdbg_copyin");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  r.r_rax = entry;
  r.r_rcx = elfldr_envp(pid);
  r.r_rdx = r.r_rsi; // argv
  r.r_rsi = r.r_rdi; // argc
  r.r_rdi = args;

  if(pt_setregs(pid, &r)) {
    perror("pt_setregs");
    return -1;
  }

  return 0;
}


/**
 * Set the name of a process.
 **/
static int
elfldr_set_procname(pid_t pid, const char* name) {
  intptr_t buf;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "pt_mmap");
    return -1;
  }

  mdbg_copyin(pid, name, buf, strlen(name)+1);
  pt_syscall(pid, SYS_thr_set_name, -1, buf);
  pt_msync(pid, buf, PAGE_SIZE, MS_SYNC);
  pt_munmap(pid, buf, PAGE_SIZE);

  return 0;
}


/**
 * Escape jail and raise privileges.
 **/
int
elfldr_raise_privileges(pid_t pid) {
  static const uint8_t caps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
				   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  intptr_t vnode;

  if(!(vnode=kernel_get_root_vnode())) {
    return -1;
  }
  if(kernel_set_proc_rootdir(pid, vnode)) {
    return -1;
  }
  if(kernel_set_proc_jaildir(pid, 0)) {
    return -1;
  }
  if(kernel_set_ucred_uid(pid, 0)) {
    return -1;
  }
  if(kernel_set_ucred_caps(pid, caps)) {
    return -1;
  }

  return 0;
}


/**
 * Execute an ELF inside the process with the given pid.
 **/
int
elfldr_exec(int stdin_fd, int stdout_fd, int stderr_fd,
	    pid_t pid, uint8_t* elf) {
  uint8_t caps[16];
  intptr_t jaildir;
  intptr_t rootdir;
  uint64_t authid;
  int error = 0;

  // backup privileges
  jaildir = kernel_get_proc_jaildir(pid);
  if(!(rootdir=kernel_get_proc_rootdir(pid))) {
    puts("kernel_get_proc_rootdir failed");
    pt_detach(pid);
    return -1;
  }
  if(kernel_get_ucred_caps(pid, caps)) {
    puts("kernel_get_ucred_caps failed");
    pt_detach(pid);
    return -1;
  }
  if(!(authid=kernel_get_ucred_authid(pid))) {
    puts("kernel_get_ucred_authid failed");
    pt_detach(pid);
    return -1;
  }

  if(elfldr_raise_privileges(pid)) {
    puts("Unable to raise privileges");
    pt_detach(pid);
    return -1;
  }

  if(stdin_fd >= 0) {
    stdin_fd = pt_rdup(pid, getpid(), stdin_fd);
    pt_close(pid, STDIN_FILENO);
    pt_dup2(pid, stdin_fd, STDIN_FILENO);
    pt_close(pid, stdin_fd);
  }
  if(stdout_fd >= 0) {
    stdout_fd = pt_rdup(pid, getpid(), stdout_fd);
    pt_close(pid, STDOUT_FILENO);
    pt_dup2(pid, stdout_fd, STDOUT_FILENO);
    pt_close(pid, stdout_fd);
  }
  if(stderr_fd >= 0) {
    stderr_fd = pt_rdup(pid, getpid(), stderr_fd);
    pt_close(pid, STDERR_FILENO);
    pt_dup2(pid, stderr_fd, STDERR_FILENO);
    pt_close(pid, stderr_fd);
  }

  if(elfldr_prepare_exec(pid, elf)) {
    error = -1;
  }

  // restore privileges
  if(kernel_set_proc_jaildir(pid, jaildir)) {
    puts("kernel_set_proc_jaildir failed");
    error = -1;
  }
  if(kernel_set_proc_rootdir(pid, rootdir)) {
    puts("kernel_set_proc_rootdir failed");
    error = -1;
  }

  if(kernel_set_ucred_caps(pid, caps)) {
    puts("kernel_set_ucred_caps failed");
    error = -1;
  }
  if(kernel_set_ucred_authid(pid, authid)) {
    puts("kernel_set_ucred_authid failed");
    error = -1;
  }

  if(pt_detach(pid)) {
    perror("pt_detach");
    error = -1;
  }

  return error;
}


/**
 * Execute an ELF inside a new process.
 **/
pid_t
elfldr_spawn(int stdin_fd, int stdout_fd, int stderr_fd,
	     uint8_t* elf, char** argv) {
  uint8_t int3instr = 0xcc;
  intptr_t brkpoint;
  uint8_t orginstr;
  pid_t pid = -1;

  if(sceKernelSpawn(&pid, 1, SceSpZeroConf, 0, argv)) {
    perror("sceKernelSpawn");
    return -1;
  }

  // The proc is now in the STOP state, with the instruction pointer pointing at
  // the libkernel entry. Insert a breakpoint at the eboot entry.
  if(!(brkpoint=kernel_dynlib_entry_addr(pid, 0))) {
    puts("kernel_dynlib_entry_addr failed");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  brkpoint += 58;// offset to invocation of main()
  if(mdbg_copyout(pid, brkpoint, &orginstr, sizeof(orginstr))) {
    perror("mdbg_copyout");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  if(mdbg_copyin(pid, &int3instr, brkpoint, sizeof(int3instr))) {
    perror("mdbg_copyin");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  // Continue execution until we hit the breakpoint, then remove it.
  if(pt_continue(pid, SIGCONT)) {
    perror("pt_continue");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  if(waitpid(pid, 0, 0) == -1) {
    perror("waitpid");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  if(mdbg_copyin(pid, &orginstr, brkpoint, sizeof(orginstr))) {
    perror("mdbg_copyin");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  // Execute the ELF
  elfldr_set_procname(pid, argv[0]);
  if(elfldr_exec(stdin_fd, stdout_fd, stderr_fd, pid, elf)) {
    kill(pid, SIGKILL);
    return -1;
  }

  return pid;
}

