/*
 * netsniff-ng - the packet sniffing beast
 * Copyright 2016 Daniel Borkmann.
 * Copyright 2016 Tobias Klauser.
 * Subject to the GPL, version 2.
 */

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>

#include "bpf_perf.h"

#define LOG_BUF_SIZE (256 * 1024)

static const char LICENSE[128] = "GPL";

static char bpf_log_buf[LOG_BUF_SIZE];

static inline __u64 bpf_ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int bpf(int cmd, union bpf_attr *attr, size_t size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static int bpf_obj_get(const char *pathname)
{
	union bpf_attr attr = {};

	attr.pathname = bpf_ptr_to_u64(pathname);

	return bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_map_lookup(int fd, const void *key, const void *value)
{
	union bpf_attr attr = {};

	attr.map_fd = fd;
	attr.key = bpf_ptr_to_u64(key);
	attr.value = bpf_ptr_to_u64(value);

	return bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static int bpf_map_update(int fd, const void *key, const void *value,
			  uint64_t flags)
{
	union bpf_attr attr = {};

	attr.map_fd = fd;
	attr.key = bpf_ptr_to_u64(key);
	attr.value = bpf_ptr_to_u64(value);
	attr.flags = flags;

	return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int bpf_prog_load(enum bpf_prog_type prog_type,
			 const struct bpf_insn *insns, size_t size_insns)
{
	union bpf_attr attr = {};

	attr.prog_type = prog_type;
	attr.insns = bpf_ptr_to_u64(insns);
	attr.insn_cnt = size_insns / sizeof(struct bpf_insn);
	attr.license = bpf_ptr_to_u64(LICENSE);
	attr.log_buf = bpf_ptr_to_u64(bpf_log_buf);
	attr.log_size = LOG_BUF_SIZE;
	attr.log_level = 1;

	bpf_log_buf[0] = 0;

	return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu,
			   int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int bpf_perf_setup()
{
	/* TODO */
	return 0;
}
