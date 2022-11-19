#ifndef GO_PROBE_EBPF_CONFIG_H
#define GO_PROBE_EBPF_CONFIG_H

#ifdef BPF_NO_GLOBAL_DATA
#define REGISTER_BASED  0
#define FRAME_POINTER   1

#define SET_CONFIG(skeleton, index, value) {                                                        \
    __u32 k = index;                                                                                \
    __u64 v = value;                                                                                \
    bpf_map__update_elem(skeleton->maps.config_map, &k, sizeof(__u32), &v, sizeof(__u64), BPF_ANY); \
}
#else
#define REGISTER_BASED  register_based
#define FRAME_POINTER   frame_pointer

#define SET_CONFIG(skeleton, entry, value) skeleton->bss->entry = value;
#endif

#endif //GO_PROBE_EBPF_CONFIG_H
