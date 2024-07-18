// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include "bpf_detector.skel.h"
#include <errno.h>
#define NO_OP 0x12345678

// static struct env {
// 	bool verbose;
// 	long min_duration_ms;
// } env;

unsigned long get_symbol_address(const char *symbol) {
    FILE *fp;
    char line[256];
    unsigned long address = 0;

    fp = fopen("/proc/kallsyms", "r");
    if (fp == NULL) {
        perror("fopen");
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, symbol)) {
            sscanf(line, "%lx", &address);
            break;
        }
    }

    fclose(fp);
    return address;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	// if (level == LIBBPF_DEBUG && !env.verbose)
	// 	return 0;
	return vfprintf(stderr, format, args);
}


static int passing_table(struct bpf_detector_bpf *skel){
	int map_fd;
    unsigned long syscall_table_address = get_symbol_address("sys_call_table");

    if (syscall_table_address == 0) {
        fprintf(stderr, "Failed to get syscall table address\n");
        return 1;
    }

    printf("Syscall table address: %lx\n", syscall_table_address);

    // 获取 BPF map 文件描述符
    map_fd = bpf_map__fd(skel->maps.syscall_table_map);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

	int key = 0;
    // 将 syscall table 地址写入 BPF map
    if (bpf_map_update_elem(map_fd, &key, &syscall_table_address, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        return 1;
    }

	printf("Syscall table address has been passed to the BPF program.\n");

	return 0;
}

void check_syscall_addresses(unsigned long text_start, unsigned long text_end,struct bpf_detector_bpf *skel) {
    int map_fd;
    int warning_counter = 0;
    unsigned long syscall_addr;
    map_fd = bpf_map__fd(skel->maps.syscall_map);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return;
    }
	printf("the map to check is : %d\n\n\n",map_fd);

    for (int i = 0; i < 449; i++) {  // 假设 sys_call_table 大小为 322
		// printf("Result is %d",bpf_map_lookup_elem(map_fd, &i, &syscall_addr));
		int idx = i;
        if (bpf_map_lookup_elem(map_fd, &idx, &syscall_addr) == 0) {
            if (syscall_addr >= text_start && syscall_addr <= text_end) {
                printf("Syscall %d address %lx is in the text segment\n", i, syscall_addr);
            } else {
                printf("\x1b[31m""WARNING!! Syscall %d address %lx is NOT in the .text segment!\n.text start at: %lx, end at : %lx\n""\x1b[0m", i, syscall_addr,text_start,text_end);
                warning_counter++;
            }
        }
    }

    if (warning_counter == 0){
        printf("\x1b[34m""Good! Nothing weird is hooked on your syscall table\n""\x1b[0m");
    }else{
        printf("\x1b[31m""Syscall table got hooked! Check the output warning!\nLook up /usr/include/asm-generic/unistd.h to see the syscall name\n""\x1b[0m");
    }
    close(map_fd);
}

int main(int argc, char **argv)
{
	int err;
	struct bpf_detector_bpf *skel;

	unsigned long text_start = get_symbol_address("_stext");
    unsigned long text_end = get_symbol_address("_etext");

	libbpf_set_print(libbpf_print_fn);
    /* Load and verify BPF application */
	skel = bpf_detector_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
    /* Load & verify BPF programs */
	err = bpf_detector_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
    /* Attach tracepoints */
	err = bpf_detector_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}


	passing_table(skel);

	int ret;
    int fd[2];
    if (pipe(fd) == -1) {
        perror("pipe");
        return 1;
    }
    ret = syscall(SYS_ioctl,fd[0],NO_OP);
	printf("%d,%d\n",errno,ret);

	check_syscall_addresses(text_start,text_end,skel);
	
	
	// printf(".text start at: %lx, end at : %lx\n", text_start, text_end);
	return 0;


cleanup:
	/* Clean up */
	bpf_detector_bpf__destroy(skel);

	return err < 0 ? -err : 0;    
}

