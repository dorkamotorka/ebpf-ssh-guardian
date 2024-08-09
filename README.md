# ebpf-ssh-guardian
Monitoring SSH Sessions using eBPF 

## eBPF Attachment

First, we need to figure out where to attach our eBPF program to track logins. 

Since we are insterested in the SSH, `sshd` (SSH Daemon) is the way to start. We figure out it's PID by using: `ps faux | grep sshd`.

Once we have the PID, we can check the linked libraries it uses using: `sudo cat /proc/<PID>/maps`

We see that it uses e.g. `/usr/lib/x86_64-linux-gnu/libpam.so.0.85.1` which is a Linux PAM (Pluggable Authentication Modules for Linux).

We can list the symbol table of the library and find the potential function we want to track using: `sudo readelf -s --wide /proc/<PID>/root/usr/lib/x86_64-linux-gnu/libpam.so.0.85.1`

We verify the function we are looking for using GitHub source-code and help ourself understand the function parameters so we can read them inside the eBPF program.
