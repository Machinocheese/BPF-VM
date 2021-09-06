## What is this?
Implements an eBPF VM in userspace, bypassing the annoyance of setting up a kernel debugging environment to test out eBPF.

I tried not to look too much at the kernel BPF handling as this was a learning exercise.
Implemented all the instructions found at: https://github.com/iovisor/bpf-docs/blob/master/eBPF.md
- there are still unused flags though, could be more eBPF instructions

### Files
- diassembler/
  - Just have the Python Capstone BPF disassembler stuff + setup instructions
- Rest of the code is the eBPF-VM.

### TO-DO (09/05/2021)
- Implement eBPF verifier
  - Basic things a verifier does:
    - DAG check to disallow loops and other CFG validation
      - disallow unreachable instructions in eBPF
    - Optional 'secure' mode where ALL pointer arithmetic is rejected
    - Make sure register has been written to before it's read from
    - load/store instructions are allowed only with registers of valid types, which
      are PTR_TO_CTX, PTR_TO_MAP, PTR_TO_STACK. They are bounds and alignment checked.
    - can only read from stack after writing to it
    - Customized function access via program type
    - Guarantee functions are called with correct arguments
    - keep track of possible values of registers (a min/max for signed/unsigned)
- Implement eBPF kernel-specific functionality
