#ifndef __BPF_PERF_H
#define __BPF_PERF_H

#include "config.h"

#ifdef HAVE_BPF_PERF
extern int bpf_perf_setup();
#else
static inline int bpf_perf_setup()
{
	return -1;
}
#endif

#endif /* __BPF_PERF_H */
