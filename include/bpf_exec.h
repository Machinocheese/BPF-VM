#ifndef __bpf_exec_h__
#define __bpf_exec_h__

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <sys/mman.h>
#include <stdio.h>
#include <string.h>
#include <endian.h>

#include "bpf_common.h"
// eBPF machine state
uint64_t registers[11]; // Composes r0-r9. r10 is readonly pointer to stack. TODO: Make r10 readonly when implementing verifier
// R0	- return value from in-kernel function, and exit value for eBPF program
// R1 - R5	- arguments from eBPF program to in-kernel function
// R6 - R9	- callee saved registers that in-kernel function will preserve
// R10	- read-only frame pointer to access stack
char* stack;
//TODO: When making verifier, handle R10 differently.

#define alu64_src_imm_op(x) if(source) registers[instr.dst_reg] = registers[instr.dst_reg] x registers[instr.src_reg]; \
                            else registers[instr.dst_reg] = registers[instr.dst_reg] x instr.imm;
#define alu_src_imm_op(x) if(source) registers[instr.dst_reg] = (uint32_t)registers[instr.dst_reg] x (uint32_t)registers[instr.src_reg]; \
                          else registers[instr.dst_reg] = (uint32_t)registers[instr.dst_reg] x (uint32_t)instr.imm;
#define jmp_src_imm_op(x, type) if(source){ \
                            if(type registers[instr.dst_reg] x type registers[instr.src_reg]) \
                              jump_offset += instr.off; \
                          } else { \
                            if(type registers[instr.dst_reg] x type instr.imm) \
                              jump_offset += instr.off; \
                          }
void create_bpf_insn(char* bytecode, int len, struct bpf_insn* code_insn);
int execute_alu64_insn(struct bpf_insn instr);
int execute_alu_insn(struct bpf_insn instr);
int execute_jmp_insn(struct bpf_insn instr);
int execute_ld_insn(struct bpf_insn instr);
int execute_ldx_insn(struct bpf_insn instr);
int execute_st_insn(struct bpf_insn instr);
int execute_stx_insn(struct bpf_insn instr);
int execute_bpf_insn(struct bpf_insn instr);
uint64_t start_bpf_vm(struct bpf_insn* code_insn, unsigned int size);

#endif
