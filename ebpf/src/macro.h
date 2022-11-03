#ifndef GO_PROBE_EBPF_MACRO_H
#define GO_PROBE_EBPF_MACRO_H

#include <bpf/bpf_tracing.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define MAX_LENGTH(length, limit) (length < limit ? (length & (limit - 1)) : limit)

#define GO_PARM1_REGS ax
#define GO_PARM2_REGS bx
#define GO_PARM3_REGS cx
#define GO_PARM4_REGS di
#define GO_PARM5_REGS si
#define GO_PARM6_REGS r8
#define GO_PARM7_REGS r9
#define GO_PARM8_REGS r10
#define GO_PARM9_REGS r11

#define GO_REGS_PARM1(x) (__PT_REGS_CAST(x)->GO_PARM1_REGS)
#define GO_REGS_PARM2(x) (__PT_REGS_CAST(x)->GO_PARM2_REGS)
#define GO_REGS_PARM3(x) (__PT_REGS_CAST(x)->GO_PARM3_REGS)
#define GO_REGS_PARM4(x) (__PT_REGS_CAST(x)->GO_PARM4_REGS)
#define GO_REGS_PARM5(x) (__PT_REGS_CAST(x)->GO_PARM5_REGS)
#define GO_REGS_PARM6(x) (__PT_REGS_CAST(x)->GO_PARM6_REGS)
#define GO_REGS_PARM7(x) (__PT_REGS_CAST(x)->GO_PARM7_REGS)
#define GO_REGS_PARM8(x) (__PT_REGS_CAST(x)->GO_PARM8_REGS)
#define GO_REGS_PARM9(x) (__PT_REGS_CAST(x)->GO_PARM9_REGS)

#endif //GO_PROBE_EBPF_MACRO_H
