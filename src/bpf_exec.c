#include "bpf_exec.h"

void create_bpf_insn(char* bytecode, int len, struct bpf_insn* code_insn){
  for(unsigned int i = 0; i < len / insn_size; i++){
    code_insn[i].code = bytecode[i * insn_size];
    code_insn[i].dst_reg = bytecode[i * insn_size + 1] & 15; // bitmask 1111
    code_insn[i].src_reg = bytecode[i * insn_size + 1] >> 4; // top 4 bits
    code_insn[i].off = bytecode[i * insn_size + 2] + bytecode[i * insn_size + 3] << 8;
    code_insn[i].imm = bytecode[i * insn_size + 4] + (bytecode[i * insn_size + 5] << 8)
                         + (bytecode[i * insn_size + 6] << 16) + (bytecode[i * insn_size + 7] << 24);
  }
}

int execute_alu64_insn(struct bpf_insn instr){
 
  uint64_t msb;
  unsigned int source = BPF_SRC(instr.code);  // if source == 1 then use src_reg for src. Otherwise use immediate
  if(instr.off){
    printf("Offset shouldn't be zero\n"); // But CAN it??
  }

  switch(BPF_OP(instr.code))
  {
    case BPF_ADD:
      alu64_src_imm_op(+);
      break;
    case BPF_SUB:
      alu64_src_imm_op(-);
      break;
    case BPF_MUL:
      alu64_src_imm_op(*);
      break;
    case BPF_DIV:
      alu64_src_imm_op(/);
      break;
    case BPF_OR:
      alu64_src_imm_op(|);
      break;
    case BPF_AND:
      alu64_src_imm_op(&);
      break;
    case BPF_LSH:
      alu64_src_imm_op(<<);
      break;
    case BPF_RSH:
      // Logical right shift. MSB is replaced with a zero.
      if(source)
        registers[instr.dst_reg] >>= registers[instr.src_reg];
      else
        registers[instr.dst_reg] >>= (uint64_t)instr.imm;   
      break;
    case BPF_NEG:
      registers[instr.dst_reg] = -registers[instr.dst_reg]; 
      break;
    case BPF_MOD:
      alu64_src_imm_op(%);
      break;
    case BPF_XOR:
      alu64_src_imm_op(^);
      break;
    case BPF_MOV:
      if(source)
        registers[instr.dst_reg] = registers[instr.src_reg];
      else
        registers[instr.dst_reg] = instr.imm;   
      break;
    case BPF_ARSH:
      // Arithmetic right shift.
      msb = registers[instr.dst_reg] & ((uint64_t)1 << 63);
      if(source){
        registers[instr.dst_reg] >>= registers[instr.src_reg];
      } else {
        registers[instr.dst_reg] >>= (uint64_t)instr.imm;   
      }
      registers[instr.dst_reg] ^= msb;
      break;
    // case BPF_END:
    // Byteswap will be dealt with in ALU32. I could only find 0xd4 and 0xdc opcodes, both of which are BPF_CLASS() == BPF_ALU
    //  Would the BPF machine recognize 0xd7 or 0xdf as a legit instruction?
    default:
      printf("Unknown instruction: %d\n", BPF_OP(instr.code));
      break;
  }

  return 1;
}

int execute_alu_insn(struct bpf_insn instr){
 
  uint32_t msb;
  unsigned int source = BPF_SRC(instr.code);
  if(instr.off){
    printf("Offset shouldn't be zero\n");
  }

  switch(BPF_OP(instr.code))
  {
    case BPF_ADD:
      alu_src_imm_op(+);
      break;
    case BPF_SUB:
      alu_src_imm_op(-);
      break;
    case BPF_MUL:
      alu_src_imm_op(*);
      break;
    case BPF_DIV:
      alu_src_imm_op(/);
      break;
    case BPF_OR:
      alu_src_imm_op(|);
      break;
    case BPF_AND:
      alu_src_imm_op(&);
      break;
    case BPF_LSH:
      alu_src_imm_op(<<);
      break;
    case BPF_RSH:
      // Logical right shift. MSB is replaced with a zero.
      if(source)
        registers[instr.dst_reg] = (uint32_t)registers[instr.dst_reg] >> (uint32_t)registers[instr.src_reg];
      else
        registers[instr.dst_reg] = (uint32_t)registers[instr.dst_reg] >> (uint32_t)instr.imm;   
      break;
    case BPF_NEG:
      registers[instr.dst_reg] = -1 * (uint32_t)registers[instr.dst_reg]; 
      break;
    case BPF_MOD:
      alu_src_imm_op(%);
      break;
    case BPF_XOR:
      alu_src_imm_op(^);
      break;
    case BPF_MOV:
      if(source)
        registers[instr.dst_reg] = (uint32_t)registers[instr.src_reg];
      else
        registers[instr.dst_reg] = (uint32_t)instr.imm;   
      break;
    case BPF_ARSH:
      // Arithmetic right shift.
      msb = (uint32_t)registers[instr.dst_reg] & ((uint32_t)1 << 31);
      if(source){
        registers[instr.dst_reg] = (uint32_t)registers[instr.dst_reg] >> (uint32_t)registers[instr.src_reg];
      } else {
        registers[instr.dst_reg] = (uint32_t)registers[instr.dst_reg] >> (uint32_t)instr.imm;   
      }
      registers[instr.dst_reg] ^= msb;
      break;
    case BPF_END:
      // ALU32-specific.
      if(source){ // Source flag for BPF_END only indicates whether you want little-endian or big-endian conversion
        if(instr.imm == 16){
          registers[instr.dst_reg] = htobe16(registers[instr.dst_reg]); 
        } else if(instr.imm == 32){
          registers[instr.dst_reg] = htobe32(registers[instr.dst_reg]);
        } else if(instr.imm == 64){
          registers[instr.dst_reg] = htobe64(registers[instr.dst_reg]); 
        }
      } else {
        if(instr.imm == 16){
          registers[instr.dst_reg] = htole16(registers[instr.dst_reg]); 
        } else if(instr.imm == 32){
          registers[instr.dst_reg] = htole32(registers[instr.dst_reg]);
        } else if(instr.imm == 64){
          registers[instr.dst_reg] = htole64(registers[instr.dst_reg]); 
        }
      }
      break;
    default:
      printf("Unknown instruction: %d\n", BPF_OP(instr.code));
      break;
  }

  return 1;
}

int execute_jmp_insn(struct bpf_insn instr){
  
  int jump_offset = 1;
  unsigned int source = BPF_SRC(instr.code);  // if source == 1 then use src_reg for src. Otherwise use immediate

  typedef void (*bpf_call)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
  bpf_call jmp_call;

  switch(BPF_OP(instr.code)){
    case BPF_JA:
      if(source){
        // Jumps over the next 'off' # of instructions
        jump_offset += instr.off;
      } 
      // there is no 'else' opcode for BPF_JA
      break;
    case BPF_JEQ:
      jmp_src_imm_op(==, (uint64_t));
      break;
    case BPF_JGT:
      jmp_src_imm_op(>, (uint64_t));
      break;
    case BPF_JGE:
      jmp_src_imm_op(>=, (uint64_t));
      break;
    case BPF_JSET:
      jmp_src_imm_op(&, (uint64_t));
      break;
    case BPF_JNE:
      jmp_src_imm_op(!=, (uint64_t));
      break;
    case BPF_JSGT: // Signed Greater-Than
      jmp_src_imm_op(>, (int64_t));
      break;
    case BPF_JSGE: // Signed Greater-Than Equals
      jmp_src_imm_op(>=, (int64_t));
      break;
    case BPF_CALL:
      // MAJOR security issue w/o a verifier. As of now? No verifier. 
      
      // YES, instr.imm is only 32-bits. Normally, in eBPF, you specify a number like '1' or '2' and eBPF will link you up
      // to the corresponding function. I'm leaving it like this until I bother implementing those 'corresponding functions'.
      jmp_call = (bpf_call) ((uint64_t)instr.imm);
      jmp_call(registers[1], registers[2], registers[3], registers[4], registers[5]);
      break;
    case BPF_EXIT:
      jump_offset = 0;
      break;
    case BPF_JLT:
      jmp_src_imm_op(<, (uint64_t));
      break;
    case BPF_JLE:
      jmp_src_imm_op(<=, (uint64_t));
      break;
    case BPF_JSLT:
      jmp_src_imm_op(<, (int64_t));
      break;
    case BPF_JSLE:
      jmp_src_imm_op(<=, (int64_t));
      break;
    default:
      printf("Unknown instruction: %d\n", BPF_OP(instr.code));
      break;
  }

  return jump_offset;
}

int execute_ld_insn(struct bpf_insn instr){

  unsigned int mode = BPF_MODE(instr.code);
  unsigned int size = BPF_SIZE(instr.code);

  switch(mode){
    case BPF_IMM:
      if(size == BPF_DW){
        registers[instr.dst_reg] = (uint64_t)instr.imm;
      }
      break;
    case BPF_ABS:
      printf("Kernel specific behavior. Currently unimplemented...\n");
      break;
    case BPF_IND:
      printf("Kernel specific behavior. Currently unimplemented...\n");
      break;
    default:
      printf("Unimplemented LD opcode:%x\n", mode);
      break;
  }

  return 1;
}

// TODO: Implement BPF_LEN + BPF_MSH related opcodes
int execute_ldx_insn(struct bpf_insn instr){

  unsigned int mode = BPF_MODE(instr.code);
  unsigned int size = BPF_SIZE(instr.code);

  if(registers[instr.src_reg] != (uint64_t)stack){
    printf("Verifier fail! Can only ldx from BPF stack\n");
    return 1;
  }

  switch(mode){
    case BPF_MEM:
      switch(size){
        case BPF_W:
          registers[instr.dst_reg] = (uint32_t)stack[instr.off];
          break;
        case BPF_H:
          registers[instr.dst_reg] = (uint16_t)stack[instr.off];
          break;
        case BPF_B:
          registers[instr.dst_reg] = (uint8_t)stack[instr.off];
          break;
        case BPF_DW:
          registers[instr.dst_reg] = (uint64_t)stack[instr.off];
          break;
        default:
          printf("Unimplemented LDX size:%x\n", size);
          break;
      }
      break;
    default:
      printf("Unimplemented LDX opcode:%x\n", mode);
      break;
  }

  return 1;
}

int execute_st_insn(struct bpf_insn instr){

  unsigned int mode = BPF_MODE(instr.code);
  unsigned int size = BPF_SIZE(instr.code);

  if(registers[instr.dst_reg] != (uint64_t)stack){
    printf("Verifier fail! Can only st to BPF stack\n");
    return 1;
  }

  switch(mode){
    case BPF_MEM:
      switch(size){
        case BPF_W:
          stack[instr.off] = (uint32_t)instr.imm;
          break;
        case BPF_H:
          stack[instr.off] = (uint16_t)instr.imm;
          break;
        case BPF_B:
          stack[instr.off] = (uint8_t)instr.imm;
          break;
        case BPF_DW:
          //TODO: Figure the point of this instr out. Isn't this basically BPF_W but with extra 0's? Why use this?
          stack[instr.off] = (uint64_t)instr.imm;
          break;
        default:
          printf("Unimplemented ST size:%x\n", size);
          break;
      }
      break;
    default:
      printf("Unimplemented ST opcode:%x\n", mode);
      break;
  }

  return 1;
}

int execute_stx_insn(struct bpf_insn instr){

  unsigned int mode = BPF_MODE(instr.code);
  unsigned int size = BPF_SIZE(instr.code);

  if(registers[instr.dst_reg] != (uint64_t)stack){
    printf("Verifier fail! Can only stx to BPF stack\n");
    return 1;
  }

  switch(mode){
    case BPF_MEM:
      switch(size){
        case BPF_W:
          stack[instr.off] = (uint32_t)registers[instr.src_reg];
          break;
        case BPF_H:
          stack[instr.off] = (uint16_t)registers[instr.src_reg];
          break;
        case BPF_B:
          stack[instr.off] = (uint8_t)registers[instr.src_reg];
          break;
        case BPF_DW:
          stack[instr.off] = (uint64_t)registers[instr.src_reg];
          break;
        default:
          printf("Unimplemented STX size:%x\n", size);
          break;
      }
      break;
    default:
      printf("Unimplemented STX opcode:%x\n", mode);
      break;
  }

  return 1;
}

// Returns the offset of the following instruction.
// Any positive number indicates that the program jumps X number of instructions ahead.
// If a -1 is returned, that means an EXIT has been signaled. Return r0.
int execute_bpf_insn(struct bpf_insn instr){
  int jump_offset = 1;
  // Simplifying the switch statement by sorting instructions based on BPF_CLASS before they then get sorted again, but in individual subfunctions.
  //uint8_t class:3 = instr.code & 7; // 3 LSB bits == instruction class
  switch(BPF_CLASS(instr.code)){
    case BPF_MISC: // in eBPF also called BPF_ALU64
      jump_offset = execute_alu64_insn(instr);
      break;
    case BPF_RET:  // in eBPF also called JMP32.
      printf("Unimplemented RET...\n");
      break;
    case BPF_JMP:
      jump_offset = execute_jmp_insn(instr);
      break;
    case BPF_ALU:
      jump_offset = execute_alu_insn(instr);
      break;
    case BPF_STX:
      jump_offset = execute_stx_insn(instr);
      break;
    case BPF_ST:
      jump_offset = execute_st_insn(instr);
      break;
    case BPF_LDX:
      jump_offset = execute_ldx_insn(instr);
      break;
    case BPF_LD:
      jump_offset = execute_ld_insn(instr);
      break;
    default:
      printf("Unknown class: %d\n", BPF_CLASS(instr.code));
      break;
  }

  for(int i = 0; i < 10; i++){
    printf("r%d: 0x%016"PRIx64"\n", i, registers[i]);
  }
  printf("\n");

  return jump_offset;
}

uint64_t start_bpf_vm(struct bpf_insn* code_insn, unsigned int size){
  unsigned int insn_ptr = 0, next_insn = 0;
  uint64_t retval = 0;
  
  // Sets up stack. Probably a safer way to do this, but it'll do for now.
  stack = (char*)mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  memset(registers, '\x00', sizeof(registers));
  registers[10] = (uint64_t)stack;
  
  while(insn_ptr < size){
    next_insn = execute_bpf_insn(code_insn[insn_ptr]);
    if(next_insn){
      // Don't think next_insn should ever be negative (No looping in BPF). Not sure though, might be possible w/ labels.
      insn_ptr += next_insn;
    } else {
      retval = registers[0];
      break;
    }
  }

  return retval;
}
