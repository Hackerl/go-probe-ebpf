#ifndef GO_PROBE_EBPF_CONFIG_H
#define GO_PROBE_EBPF_CONFIG_H

#ifdef BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, int);
} config_map SEC(".maps");
#else
int register_based = 0;
#endif

static __always_inline int is_register_based() {
#ifdef BPF_NO_GLOBAL_DATA
    __u32 index = 0;
    int *config = bpf_map_lookup_elem(&config_map, &index);

    if (!config)
        return 0;

    return *config;
#else
    return register_based;
#endif
}

#endif //GO_PROBE_EBPF_CONFIG_H
