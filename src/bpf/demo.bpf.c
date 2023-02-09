#include "demo.h"

static const struct event empty_event = {};

// Dummy instance to get skeleton to generate definition for `struct event`
struct event _event = {0};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, pid_t);
	__type(value, struct event);
} execs SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

/*
 * /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve
 * 通过监控内核中系统调用execve
 * 当系统中调用了这个系统调用的话就会调用mybpfprog函数
 *
 * 编译好程序后执行./demo
 *
 * 然后打开一个新终端,输入一些命令即可看到结果
 */
SEC("tracepoint/syscalls/sys_enter_execve")
int syscalls__sys_enter_execve(struct pt_regs *ctx)
{

	u64 id;
	pid_t pid, tgid;

	char msg[] = "started";
	bpf_trace_printk(msg, sizeof(msg));

	struct event *event;

	struct task_struct *task;

	task = (struct task_struct*)bpf_get_current_task();

	uid_t uid = (u32)bpf_get_current_uid_gid();
	int i;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;

	if (bpf_map_update_elem(&execs, &pid, &empty_event, BPF_NOEXIST))
		return 0;

	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	event->pid = tgid;
	event->uid = uid;

	event->ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

	return 0;
}

// SEC("tracepoint/syscalls/sys_exit_execve")
// int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_exit* ctx)
// {
// // 	u64 id;
// // 	pid_t pid;
// // 	int ret;
// // 	struct event *event;

// // 	u32 uid = (u32)bpf_get_current_uid_gid();

// // 	id = bpf_get_current_pid_tgid();
// // 	pid = (pid_t)id;
// // 	event = bpf_map_lookup_elem(&execs, &pid);
// // 	if (!event)
// // 		return 0;
// // 	ret = ctx->ret;

// // 	event->retval = ret;
// // 	bpf_get_current_comm(&event->comm, sizeof(event->comm));
// // 	size_t len =((size_t)(&((struct event*)0)->args) + event->args_size);
// // 	if (len <= sizeof(*event))

// // cleanup:
// // 	bpf_map_delete_elem(&execs, &pid);
// 	return 0;
// }

char LICENSE[] SEC("license") = "GPL";
