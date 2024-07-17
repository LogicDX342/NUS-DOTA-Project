#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_defender.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} my_ringbuf SEC(".maps");

struct value_t {
	__u32 id;
	char value[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct value_t));
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, struct value_t);
} input_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(struct event));
	__uint(max_entries, 128 * 1024);
	__type(key, int);
	__type(value, struct event);
} proc_map SEC(".maps");

static int strncmp(const char *cs, size_t count, const char *ct)
{
	unsigned char c1, c2;
	int res = 0;

	for (size_t i = 0; i < count; i++) {
		c1 = cs[i];
		c2 = ct[i];
		if (c1 != c2) {
			res = c1 < c2 ? -1 : 1;
			break;
		}
		if (!c1)
			break;
	}
	return res;
}

char pwd[64] = "pwd";
static int check_password(char *input)
{
	if (strncmp(pwd, sizeof(pwd), input) == 0) {
		return 1;
	}
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct event e = {
		.pid = bpf_get_current_pid_tgid() >> 32,
		.ppid = BPF_CORE_READ(task, real_parent, tgid),
		.comm = { 0 },
		.filename = { 0 },
		.waiting_for_password = true,
		.authroized = false,
	};

	bpf_get_current_comm(&e.comm, sizeof(e.comm));
	unsigned fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e.filename, sizeof(e.filename), (void *)ctx + fname_off);
	bpf_map_update_elem(&proc_map, &e.pid, &e, BPF_ANY);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	bpf_map_delete_elem(&proc_map, &pid);
	return 0;
}

pid_t unauth_event = 0;
pid_t my_pid = 0;
SEC("tp/syscalls/sys_enter_kill")
int handle_kill(struct trace_event_raw_sys_enter *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	if (ctx->args[1] != 0 || pid != my_pid) {
		return 0;
	}

	struct event *e = bpf_map_lookup_elem(&proc_map, &unauth_event);
	if (!e) {
		bpf_printk("Failed to lookup process map\n");
		return 0;
	}
	e->waiting_for_password = false;

	int key = 0;
	char *input = bpf_map_lookup_elem(&input_map, &key);
	if (input && check_password(input)) {
		if (bpf_map_delete_elem(&input_map, &key)) {
			bpf_printk("Failed to delete input map\n");
		}
		e->authroized = true;
	} else {
		e->authroized = false;
	}
	bpf_ringbuf_output(&my_ringbuf, e, sizeof(*e), 0);
	e = NULL;
	return 0;
}

SEC("tp/syscalls/sys_enter_bpf")
int handle_tp(struct trace_event_raw_sys_enter *ctx)
{
	if (ctx->args[0] != BPF_PROG_LOAD) {
		return 0;
	}

	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct event *e = bpf_map_lookup_elem(&proc_map, &pid);
	if (!e) {
		bpf_printk("Failed to lookup process map\n");
		return 0;
	}

	if (e->authroized) {
		return 0;
	}
	bpf_ringbuf_output(&my_ringbuf, e, sizeof(*e), 0);

	e->waiting_for_password = true;
	bpf_send_signal(19);
	unauth_event = e->pid;
	return 0;
}