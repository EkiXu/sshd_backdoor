# libbpf-rust-demo

## generate vmlinux.h
To generate an updated `vmlinux.h`:
```shell
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h
```

## debug

bpf_printk will output to

```
sudo cat  /sys/kernel/debug/tracing/trace_pipe
```

## trace points information

You can execute ``sudo ls /sys/kernel/debug`` to query the kernel debug file system for specific information.

For example, the following command can be executed in order to query the parameter format of the execve system call.

```
# in case of missing file, try to mount debugfs
# sudo mount -t debugfs debugfs /sys/kernel/debug

sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format

->
name: sys_enter_execve
ID: 716
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char * filename;    offset:16;      size:8; signed:0;
        field:const char *const * argv; offset:24;      size:8; signed:0;
        field:const char *const * envp; offset:32;      size:8; signed:0;

print fmt: "filename: 0x%08lx, argv: 0x%08lx, envp: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->argv)), ((unsigned long)(REC->envp))
```

> https://time.geekbang.org/column/article/484207

## map

> https://arthurchiao.art/blog/bpf-advanced-notes-2-zh/#%E5%9C%BA%E6%99%AF%E4%B8%80%E6%9B%B4%E9%AB%98%E6%95%88%E4%BF%9D%E8%AF%81%E4%BA%8B%E4%BB%B6%E9%A1%BA%E5%BA%8F%E5%9C%B0%E5%BE%80%E7%94%A8%E6%88%B7%E7%A9%BA%E9%97%B4%E5%8F%91%E9%80%81%E6%95%B0%E6%8D%AE
