#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "bpf_exec.h"

const unsigned int insn_size = sizeof(struct bpf_insn);

// Extremely basic stuff to confirm bytecode is valid. Nothing complex like the verifier does.
int basic_verify_bytecode(char* bytecode, int len){
  if( len % insn_size != 0 ){
    return 0;
  }

  return 1;
}

int main(int argc, char** argv){
  //char* bytecode = "\x97\x09\x00\x00\x37\x13\x03\x00\xdc\x02\x00\x00\x20\x00\x00\x00";
  //int bytecode_len = 16;
  //char* bytecode = "\xb7\x03\x00\x00\x2a\x00\x00\x00\x0f\x30\x00\x00\x00\x00\x00\x00";
  char* bytecode = "\xb7\x03\x00\x00\x2a\x00\x00\x00\x15\x00\x02\x00\x00\x00\x00\x00";
  int bytecode_len = 16;
  
  if(!basic_verify_bytecode(bytecode, bytecode_len)){
    printf("Failed to meet basic bytecode verifications\n");
    return -1;
  }

  // I'm reformatting the bytecode data structure, shouldn't need to malloc more data
  struct bpf_insn* code_insn = (struct bpf_insn*) malloc(bytecode_len);
  create_bpf_insn(bytecode, bytecode_len, code_insn);

  start_bpf_vm(code_insn, bytecode_len / insn_size);
  free(code_insn);
  return 0;
}
