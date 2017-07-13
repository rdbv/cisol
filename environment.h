#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#define MEMORY_SIZE 1024

bool of = 0, sf = 0, zf = 0, af = 0, pf = 0, cf = 0;

union {
    uint64_t tmp64;
    uint32_t tmp32;
    uint16_t tmp16;
    uint8_t tmp8;
} tmp;

#define tmp8 tmp.tmp8
#define tmp16 tmp.tmp16
#define tmp32 tmp.tmp32
#define tmp64 tmp.tmp64

#define MEMORY(T, O) (*((T*)&memory[O]))

#define TMP8(x, op, y)   tmp8  = ((uint8_t)x)  op ((uint8_t)y)
#define TMP16(x, op, y)  tmp16 = ((uint16_t)x) op ((uint16_t)y)
#define TMP32(x, op, y)  tmp32 = ((uint32_t)x) op ((uint32_t)y)
#define TMP64(x, op, y)  tmp64 = ((uint64_t)x) op ((uint64_t)y)

/* 
 * Flags stuff 
 * Thanks @bochs, i was looking at your code with flags a bit
 */

#define SET_ZF(size) zf = !tmp##size

#define SET_CF_ADD(size, op1)  cf = tmp##size < op1
#define SET_CF_ADC(size, op1)  cf = tmp##size <= op1


#define SET_CF_SUB(op1, op2)   cf = op1 < op2
#define SET_CF_SBB(size, op1, op2, cnst) cf = (op1 < tmp##size) || (op2 == cnst)

// Much instrucions
#define SET_AF_0(op1, op2) af = ((op1 ^ op2) ^ tmp8) & 0x10

#define SET_AF_INC(size) af = (tmp##size & 0xf) == 0
#define SET_AF_DEC(size) af = (tmp##size & 0xf) == 0xf

#define SET_OF_SUB(op1, op2, size, mask) \
    of = (((((op1) ^ (op2)) & ((op1) ^ (tmp##size))) & (mask)) != 0)

#define SET_OF_ADD(op1, op2, result, mask) \
    of = (((((op1) ^ (result)) & ((op2) ^ (result))) & (mask)) != 0)


#define SET_OF_INC_DEC_NEG(size, mask) \
    of = (tmp##size == mask)


/*
 * We are emulating only fragment of stack
 */
uint8_t memory[MEMORY_SIZE] = {0};

/* Registers */

struct {
    union {
        struct {
            uint8_t al;
            uint8_t ah;
        } __attribute__((packed));
        uint16_t ax;
        uint32_t eax;
        uint64_t rax;
    } __attribute__((packed));

    union {
        struct {
            uint8_t bl;
            uint8_t bh;
        } __attribute__((packed));
        uint16_t bx;
        uint32_t ebx;
        uint64_t rbx;
    } __attribute__((packed));

    union {
        struct {
            uint8_t cl;
            uint8_t ch;
        } __attribute__((packed));
        uint16_t cx;
        uint32_t ecx;
        uint64_t rcx;
    } __attribute__((packed));

    union {
        struct {
            uint8_t dl;
            uint8_t dh;
        } __attribute__((packed));
        uint16_t dx;
        uint32_t edx;
        uint64_t rdx;
    } __attribute__((packed));

    union {
        struct {
            uint8_t bpl;
            uint8_t bph;
        } __attribute__((packed));
        uint16_t bp;
        uint32_t ebp;
        uint64_t rbp;
    } __attribute__((packed));

} __attribute__((packed)) regs;


#define rax regs.rax
#define eax regs.eax
#define  ax regs.ax
#define  al regs.al
#define  ah regs.ah

#define rbx regs.rbx
#define ebx regs.ebx
#define  bx regs.bx
#define  bl regs.bl
#define  bh regs.bh

#define rcx regs.rcx
#define ecx regs.ecx
#define  cx regs.cx
#define  cl regs.cl
#define  ch regs.ch

#define rdx regs.rdx
#define edx regs.edx
#define  dx regs.dx
#define  dl regs.dl
#define  dh regs.dh

#define rbp regs.rbp
#define ebp regs.ebp
#define  bp regs.bp
#define  bl regs.bl
#define  bh regs.bh


