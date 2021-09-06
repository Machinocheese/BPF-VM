# BPF-VM
- diassembler/
  - Just have the Python Capstone BPF disassembler stuff + setup instructions

- Rest of the code (the CMakeLists.txt) is emulating eBPF behavior in userspace w/o potentially setting up a kernel to debug.
- I didn't look at the kernel's BPF handling code, mainly b/c this was a coding exercise.

## TO-DO (09/05/2021)
- Implement eBPF verifier
- Implement eBPF kernel-specific functionality
