// Just took a bunch of structs / definitions from the kernel source.

struct bpf_insn {
	uint8_t	code;		/* opcode */
	uint8_t	dst_reg:4;	/* dest register */
	uint8_t	src_reg:4;	/* source register */
	int16_t	off;		/* signed offset */
	int32_t	imm;		/* signed immediate constant */
};
const unsigned int insn_size = sizeof(struct bpf_insn);

// Instruction classes
#define BPF_CLASS(code) ((code) & 0x07)
#define		BPF_LD		0x00
#define		BPF_LDX		0x01
#define		BPF_ST		0x02
#define		BPF_STX		0x03
#define		BPF_ALU		0x04
#define		BPF_JMP		0x05
#define		BPF_RET		0x06
#define		BPF_MISC        0x07

// ld/ldx fields
#define BPF_SIZE(code)  ((code) & 0x18)
#define		BPF_W		0x00 // 32-bit
#define		BPF_H		0x08 // 16-bit
#define		BPF_B		0x10 //  8-bit
// eBPF		BPF_DW		0x18    64-bit
#define BPF_MODE(code)  ((code) & 0xe0)
#define		BPF_IMM		0x00
#define		BPF_ABS		0x20
#define		BPF_IND		0x40
#define		BPF_MEM		0x60
#define		BPF_LEN		0x80
#define		BPF_MSH		0xa0

// alu/jmp fields
#define BPF_OP(code)    ((code) & 0xf0)
#define		BPF_ADD		0x00
#define		BPF_SUB		0x10
#define		BPF_MUL		0x20
#define		BPF_DIV		0x30
#define		BPF_OR		0x40
#define		BPF_AND		0x50
#define		BPF_LSH		0x60
#define		BPF_RSH		0x70
#define		BPF_NEG		0x80
#define		BPF_MOD		0x90
#define		BPF_XOR		0xa0
#define   BPF_MOV   0xb0 // eBPF only
#define   BPF_ARSH  0xc0 // eBPF only
#define   BPF_END   0xd0 // eBPF only

#define		BPF_JA		0x00 // BPF_JMP only
#define		BPF_JEQ		0x10
#define		BPF_JGT		0x20
#define		BPF_JGE		0x30
#define		BPF_JSET  0x40
#define   BPF_JNE   0x50  // eBPF only: jump !=
#define   BPF_JSGT  0x60  // eBPF only: signed '>'
#define   BPF_JSGE  0x70  // eBPF only: signed '>='
#define   BPF_CALL  0x80  // eBPF BPF_JMP only: function call
#define   BPF_EXIT  0x90  // eBPF BPF_JMP only: function return
#define   BPF_JLT   0xa0  // eBPF only: unsigned '<'
#define   BPF_JLE   0xb0  // eBPF only: unsigned '<='
#define   BPF_JSLT  0xc0  // eBPF only: signed '<'
#define   BPF_JSLE  0xd0  // eBPF only: signed '<='

#define BPF_SRC(code)   ((code) & 0x08)
#define		BPF_K		0x00
#define		BPF_X		0x08

#define BPF_MAXINSNS 4096
