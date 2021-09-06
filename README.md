## What is this?
Implements an eBPF VM in userspace, bypassing the annoyance of setting up a kernel debugging environment to test out eBPF.

I tried not to look too much at the kernel BPF handling as this was a learning exercise.

### Files
- diassembler/
  - Just have the Python Capstone BPF disassembler stuff + setup instructions
- Rest of the code is the eBPF-VM.

### TO-DO (09/05/2021)
- Implement eBPF verifier
- Implement eBPF kernel-specific functionality
