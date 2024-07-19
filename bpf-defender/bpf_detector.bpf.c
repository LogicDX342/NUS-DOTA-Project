#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, unsigned long);
} syscall_table_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 449);
    __type(key, int);
    __type(value, unsigned long);
} syscall_map SEC(".maps");

SEC("tp/syscalls/sys_enter_ioctl")
int checker(struct pt_regs *ctx)
{
    bpf_printk("yes2\n");
    
    // unsigned long cmd = PT_REGS_PARM2(ctx);
    // unsigned long cmd = 2;
    // bpf_printk("%d",cmd);
    // if(cmd != 0x12345678)
    //     return 0;
    
    int key = 0;
    unsigned long *syscall_table_address;
    syscall_table_address = bpf_map_lookup_elem(&syscall_table_map, &key);
    if (!syscall_table_address) {
        return 0;
    }

    int idx = 0;
    for (size_t i = 0; i < 449; i++) {
        idx = i;
        unsigned long syscall_addr;

        bpf_probe_read_kernel(&syscall_addr, sizeof(syscall_addr), (void *)(*syscall_table_address + idx * sizeof(unsigned long)));

        bpf_printk("%d",bpf_map_update_elem(&syscall_map, &idx, &syscall_addr, BPF_ANY));
        bpf_printk("key:%d  syscall_addr:%lx\n %d", idx, syscall_addr);
    }

    bpf_printk("done");

    return 0;
}