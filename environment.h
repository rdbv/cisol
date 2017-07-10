#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#define MEMORY_SIZE 1024

uint8_t  of = 0, sf = 0, zf = 0, af = 0, pf = 0, cf = 0;
uint8_t  tmp8   = 0;
uint16_t tmp16  = 0;
uint32_t tmp32  = 0;
uint64_t tmp64  = 0;

#define MEMORY_SET(T, O, V) *((T*)&memory[O]) = V
#define MEMORY_GET(T, O) (*((T*)&memory[O]))
#define IS_EQUAL(T, O, V) MEMORY_GET(T, O) == V

#define TMP8(x, op, y)   tmp8  = ((uint8_t)x)  op ((uint8_t)y)
#define TMP16(x, op, y)  tmp16 = ((uint16_t)x) op ((uint16_t)y)
#define TMP32(x, op, y)  tmp32 = ((uint32_t)x) op ((uint32_t)y)
#define TMP64(x, op, y)  tmp64 = ((uint64_t)x) op ((uint64_t)y)

#define ZF8() zf = !tmp8
#define ZF16() zf = !tmp16
#define ZF32() zf = !tmp32
#define ZF64() zf = !tmp64

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

