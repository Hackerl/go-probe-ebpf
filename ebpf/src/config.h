#ifndef GO_PROBE_EBPF_CONFIG_H
#define GO_PROBE_EBPF_CONFIG_H

#include <stdbool.h>

#ifdef BPF_NO_GLOBAL_DATA
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define REGISTER_BASED  0
#define FRAME_POINTER   1

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} config_map SEC(".maps");
#else
bool register_based = false;
bool frame_pointer = false;
#endif

static __always_inline bool is_register_based() {
#ifdef BPF_NO_GLOBAL_DATA
    __u32 index = REGISTER_BASED;
    __u64 *config = bpf_map_lookup_elem(&config_map, &index);

    if (!config)
        return 0;

    return *config;
#else
    return register_based;
#endif
}

static __always_inline bool has_frame_pointer() {
#ifdef BPF_NO_GLOBAL_DATA
    __u32 index = FRAME_POINTER;
    __u64 *config = bpf_map_lookup_elem(&config_map, &index);

    if (!config)
        return 0;

    return *config;
#else
    return frame_pointer;
#endif
}

#endif //GO_PROBE_EBPF_CONFIG_H
