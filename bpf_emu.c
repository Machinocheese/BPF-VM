#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "bpf_common.h"

// eBPF machine state
int64_t registers[10] = {0}; // Composes r0-r9. r10 is readonly pointer to stack, no need to declare it here
const void* stack;

// Extremely basic stuff to confirm bytecode is valid. Nothing complex like the verifier does.
int basic_verify_bytecode(char* bytecode, int len){
  if( len % insn_size != 0 ){
    return 0;
  }

  return 1;
}

void create_bpf_insn(char* bytecode, int len, struct bpf_insn* code_insn){
  for(int i = 0; i < len / insn_size; i++){
    code_insn[i].code = bytecode[i * insn_size];
    code_insn[i].dst_reg = bytecode[i * insn_size + 1] & 15; // bitmask 1111
    code_insn[i].src_reg = bytecode[i * insn_size + 1] >> 4; // top 4 bits
    code_insn[i].off = bytecode[i * insn_size + 2] + bytecode[i * insn_size + 3] << 8;
    code_insn[i].imm = bytecode[i * insn_size + 4] + (bytecode[i * insn_size + 5] << 8)
                         + (bytecode[i * insn_size + 6] << 16) + (bytecode[i * insn_size + 7] << 24);
  }
}

#define src_imm_op(x) if(source) registers[instr.dst_reg] = registers[instr.dst_reg] x registers[instr.src_reg]; else registers[instr.dst_reg] = registers[instr.dst_reg] x instr.imm;
void execute_alu64_insn(struct bpf_insn instr){
 
  int source = BPF_SRC(instr.code);  // if source == 1 then use src_reg for src. Otherwise use immediate
  if(instr.off){
    printf("Offset shouldn't be zero\n"); // But CAN it??
  }

  printf("%d\n", BPF_OP(instr.code));
  if (BPF_OP(instr.code) == BPF_ADD){
    src_imm_op(+);
    /*
    if(source)
      registers[instr.dst_reg] += registers[instr.src_reg];
    else
      registers[instr.dst_reg] += instr.imm;   
    */
  } /*else if (BPF_OP(instr.code) & BPF_SUB){
   
  } else if (BPF_OP(instr.code) & BPF_MUL){
  
  } else if (BPF_OP(instr.code) & BPF_DIV){
  
  } else if (BPF_OP(instr.code) & BPF_OR){
  
  } else if (BPF_OP(instr.code) & BPF_AND){
  
  } else if (BPF_OP(instr.code) & BPF_LSH){
  
  } else if (BPF_OP(instr.code) & BPF_RSH){
  
  } else if (BPF_OP(instr.code) & BPF_NEG){
  
  } else if (BPF_OP(instr.code) & BPF_MOD){
  
  } else if (BPF_OP(instr.code) & BPF_XOR){
  
  }*/ else if (BPF_OP(instr.code) & BPF_MOV){
    if(source)
      registers[instr.dst_reg] = registers[instr.src_reg];
    else
      registers[instr.dst_reg] = instr.imm;   
  } /*else if (BPF_OP(instr.code) & BPF_ARSH){
  
  } else if (BPF_OP(instr.code) & BPF_END){
  
  } else {
    printf("Should never reach here\n");
  }
  */
}
void execute_bpf_insn(struct bpf_insn instr){
  // Instead of making a massive switch statement, first sort the instructions out based on functionality before branching into smaller switches in subfunctions.
  //uint8_t class:3 = instr.code & 7; // 3 LSB bits == instruction class
  if (BPF_CLASS(instr.code) & BPF_MISC){ // in eBPF also called BPF_ALU64
    execute_alu64_insn(instr); 
  } else if (BPF_CLASS(instr.code) & BPF_RET){ // in eBPF also called JMP32
    printf("Unimplemented RET...\n"); 
  } else if (BPF_CLASS(instr.code) & BPF_JMP){
    printf("Unimplemented JMP...\n"); 
  } else if (BPF_CLASS(instr.code) & BPF_ALU){
    printf("Unimplemented ALU...\n"); 
  } else if (BPF_CLASS(instr.code) & BPF_ST){ 
    printf("Unimplemented ST...\n");
  } else if (BPF_CLASS(instr.code) & BPF_LDX){
    printf("Unimplemented LDX...\n"); 
  } else if (BPF_CLASS(instr.code) == BPF_LD){
    printf("Unimplemented LD...\n");
  } else {
    printf("Should never reach here\n");
  }

  for(int i = 0; i < 10; i++){
    printf("Register %d: 0x%x\n", i, registers[i]);
  }

  // TODO: should return the next instruction (or some hint of it...)
}

int main(int argc, char** argv){
  //char* bytecode = "\x97\x09\x00\x00\x37\x13\x03\x00\xdc\x02\x00\x00\x20\x00\x00\x00";
  //int bytecode_len = 16;
  char* bytecode = "\xb7\x03\x00\x00\x2a\x00\x00\x00\x0f\x30\x00\x00\x00\x00\x00\x00";
  int bytecode_len = 16;
  
  if(!basic_verify_bytecode(bytecode, bytecode_len)){
    printf("Failed to meet basic bytecode verifications\n");
    return -1;
  }

  // Sets up stack. Probably a safer way to do this, but it'll do for now.
  stack = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);

  // I'm reformatting the bytecode data structure, shouldn't need to malloc more data
  struct bpf_insn* code_insn = (struct bpf_insn*) malloc(bytecode_len);
  create_bpf_insn(bytecode, bytecode_len, code_insn);

  //curr_insn = code_insn[0];
  execute_bpf_insn(code_insn[0]);
  execute_bpf_insn(code_insn[1]);
  free(code_insn);
  return 1;
}
