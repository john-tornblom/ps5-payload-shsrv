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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>
#include <ps5/payload.h>

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

  if((addr=pt_mmap(ctx->pid, addr, memsz, PROT_WRITE | PROT_READ,
		   MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
		   -1, 0)) == -1) {
    pt_perror(ctx->pid, "[elfldr.elf] mmap");
    return -1;
  }

  if(mdbg_copyin(ctx->pid, ctx->elf+phdr->p_offset, addr, phdr->p_memsz)) {
    pt_perror(ctx->pid, "[elfldr.elf] mdbg_copyin");
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

  if(!(data=malloc(memsz))) {
    perror("[elfldr.elf] malloc");
    return -1;
  }

  // Backup data
  else if(mdbg_copyout(ctx->pid, addr, data, memsz)) {
    pt_perror(ctx->pid, "[elfldr.elf] mdbg_copyout");
    error = -1;
  }

  // Create shm with executable permissions.
  else if((shm_fd=pt_jitshm_create(ctx->pid, 0, memsz,
				   prot | PROT_READ | PROT_WRITE)) < 0) {
    pt_perror(ctx->pid, "[elfldr.elf] jitshm_create");
    error = -1;
  }

  // Map shm into an executable address space.
  else if((addr=pt_mmap(ctx->pid, addr, memsz, prot,
			MAP_FIXED | MAP_PRIVATE,
			shm_fd, 0)) == -1) {
    pt_perror(ctx->pid, "[elfldr.elf] mmap");
    error = -1;
  }

  // Create an shm alias fd with write permissions.
  else if((alias_fd=pt_jitshm_alias(ctx->pid, shm_fd,
				    PROT_READ | PROT_WRITE)) < 0) {
    pt_perror(ctx->pid, "[elfldr.elf] jitshm_alias");
    error = -1;
  }

  // Map shm alias into a writable address space.
  else if((addr=pt_mmap(ctx->pid, 0, memsz, PROT_READ | PROT_WRITE, MAP_SHARED,
			alias_fd, 0)) == -1) {
    pt_perror(ctx->pid, "[elfldr.elf] mmap");
    error = -1;
  }

  // Resore data
  else {
    if(mdbg_copyin(ctx->pid, data, addr, memsz)) {
      pt_perror(ctx->pid, "[elfldr.elf] mdbg_copyin");
      error = -1;
    }
    pt_munmap(ctx->pid, addr, memsz);
  }

  free(data);
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
    puts("[elfldr.elf] elfldr_load: Malformed ELF file");
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
    puts("[elfldr.elf] elfldr_load: ELF type not supported");
    return 0;
  }

  // Reserve an address space of sufficient size.
  if((ctx.base_addr=pt_mmap(pid, ctx.base_addr, ctx.base_size, prot,
			    flags, -1, 0)) == -1) {
    pt_perror(pid, "[elfldr.elf] pt_mmap");
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
	pt_perror(pid, "[elfldr.elf] pt_mprotect");
	error = 1;
      }
    }
  }

  if(error) {
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    return 0;
  }

  return ctx.base_addr + ehdr->e_entry;
}


/**
 * Create payload args in the address space of the process with the given pid.
 **/
static intptr_t
elfldr_payload_args(pid_t pid) {
  intptr_t buf;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "[elfldr.elf] pt_mmap");
    return 0;
  }

  intptr_t args       = buf;
  intptr_t rwpipe     = buf + 0x100;
  intptr_t rwpair     = buf + 0x200;
  intptr_t payloadout = buf + 0x300;

  intptr_t dlsym = pt_resolve(pid, "LwG8g3niqwA");

  int master_sock = payload_get_args()->rwpair[0];
  int victim_sock = payload_get_args()->rwpair[1];

  int pipe0 = payload_get_args()->rwpipe[0];
  int pipe1 = payload_get_args()->rwpipe[1];

  intptr_t kpipe_addr = kernel_get_proc_file(pid, pipe0);

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


static int
elfldr_raise_privileges(pid_t pid) {
  uint8_t caps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  intptr_t vnode;

  if(!(vnode=kernel_get_root_vnode())) {
    puts("[elfldr.elf] kernel_get_root_vnode() failed");
    return -1;
  }
  if(kernel_set_proc_rootdir(pid, vnode)) {
    puts("[elfldr.elf] kernel_set_proc_rootdir() failed");
    return -1;
  }
  if(kernel_set_ucred_uid(pid, 0)) {
    puts("[elfldr.elf] kernel_set_ucred_uid() failed");
    return -1;
  }

  if(kernel_set_ucred_caps(pid, caps)) {
    puts("[elfldr.elf] kernel_set_ucred_caps() failed");
    return -1;
  }

  return 0;
}


static int
elfldr_prepare_exec(pid_t pid, uint8_t *elf) {
  intptr_t entry;
  struct reg r;

  if(pt_getregs(pid, &r)) {
    perror("[elfldr.elf] pt_getregs");
    return -1;
  }

  if(!(entry=elfldr_load(pid, elf))) {
    puts("[elfldr.elf] elfldr_load() failed");
    return -1;
  }

  r.r_rip = entry;
  r.r_rsi = pt_getint(pid, r.r_rdi); // argc
  r.r_rdx = r.r_rdi + 0x8;           // argv
  r.r_r10 = 0;                       // envp
  r.r_rdi = elfldr_payload_args(pid);

  if(pt_setregs(pid, &r)) {
    perror("[elfldr.elf] pt_setregs");
    return -1;
  }

  return 0;
}


static int
elfldr_set_procname(pid_t pid, const char* name) {
  intptr_t buf;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "[elfldr.elf] pt_mmap");
    return -1;
  }

  mdbg_copyin(pid, name, buf, strlen(name));
  pt_syscall(pid, SYS_thr_set_name, -1, buf);
  pt_munmap(pid, buf, PAGE_SIZE);

  return 0;
}


/**
 *
 **/
static int
elfldr_spawn(const char* binpath, char* const argv[]) {
  pid_t pid;

  if((pid=syscall(SYS_fork))) {
    return pid;
  }

  syscall(SYS_thr_set_name, -1, argv[0]);
  if(pt_trace_me() < 0) {
    perror("pt_trace_me");
    _exit(errno);
  }

  if(execve(binpath, argv, 0) < 0) {
    perror("execve");
    _exit(errno);
  }

  return -1;
}


int
elfldr_exec(uint8_t *elf, char* argv[]) {
  uint8_t int3instr = 0xcc;
  struct kevent evt;
  intptr_t brkpoint;
  pid_t pid = -1;
  int kq;

  if((kq=kqueue()) < 0) {
    perror("kqueue");
    return -1;
  }

  if((pid=elfldr_spawn("/system/vsh/app/NPXS40112/eboot.bin", argv)) < 0) {
    close(kq);
    return -1;
  }

  EV_SET(&evt, pid, EVFILT_PROC, EV_ADD, NOTE_EXEC | NOTE_EXIT, 0, NULL);
  if(kevent(kq, &evt, 1, &evt, 1, NULL) < 0) {
    perror("kevent");
    pt_continue(pid, SIGKILL);
    pt_detach(pid);
    close(kq);
    return -1;
  }

  close(kq);
  if(waitpid(pid, 0, 0) < 0) {
    perror("waitpid");
    pt_continue(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  if(!(brkpoint=kernel_dynlib_entry_addr(pid, 0))) {
    puts("[elfldr.elf] kernel_dynlib_entry_addr() failed");
    pt_continue(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  if(mdbg_copyin(pid, &int3instr, brkpoint, sizeof(int3instr))) {
    perror("[elfldr.elf] mdbg_copyin");
    pt_continue(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  if(pt_continue(pid, SIGCONT)) {
    perror("[elfldr.elf] pt_continue");
    pt_continue(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  if(waitpid(pid, 0, 0) == -1) {
    perror("[elfldr.elf] waitpid");
    pt_continue(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  if(elfldr_raise_privileges(pid)) {
    puts("[elfldr.elf] Unable to raise privileges");
    pt_continue(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  if(elfldr_prepare_exec(pid, elf)) {
    pt_continue(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  elfldr_set_procname(pid, argv[0]);
  if(pt_detach(pid)) {
    perror("[elfldr.elf] pt_detach");
    return -1;
  }

  return pid;
}

