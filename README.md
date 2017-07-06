
```
bin/main:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	b0 0a                	mov    al,0xa
  400082:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  400085:	48 8b 5d e0          	mov    rbx,QWORD PTR [rbp-0x20]
```

translate to


```
#include <stdint.h>
#define MEMORY_SIZE 1024

uint8_t of = 0, sf = 0, zf = 0, af = 0, pf = 0, cf = 0;
uint8_t  tmp8   = 0;
uint16_t tmp16  = 0;
uint32_t tmp32  = 0;
uint64_t tmp64  = 0;

#define MEMORY_SET(T, O, V) *((T*)&stack[O]) = V
#define MEMORY_GET(T, O) (*((T*)&stack[O]))

uint8_t memory[MEMORY_SIZE] = {0};

struct {
    union {
        uint64_t regs64[17];
        struct {
            uint64_t rax, rbx, rcx,
                     rdx, rsi, rdi,
                     r8,  r9,  r10,
                     r11, r12, r13,
                     r14, r15, rip,
                     rbp, rsp;
        };
        uint32_t regs32[17];
        struct {
            uint32_t eax,  ebx,  ecx,
                     edx,  esi,  edi,
                     r8d,  r9d,  r10d,
                     r11d, r12d, r13d,
                     r14d, r15d, eip,
                     ebp, esp;
        };
        uint16_t regs16[17];
        struct {
            uint16_t ax, bx, cx,
                     dx, si, di,
                     r8w, r9w, r10w,
                     r11w, r12w, r13w,
                     r14w, r15w, ip,
                     bp, sp;
        };
        uint8_t regs8[34];
        /* rNx/bpl/eg. don't exist, but must (i think so.. xD) be here for padding */
        struct {
            uint8_t al, ah, bl, bh, cl, ch,
                    dl, dh, sil, sih, dil, dih,
                    r8b, r8x, r9b, r9x, r10b, r10x,
                    r11b, r11x, r12b, r12x, r13b, r13x,
                    r14b, r14x, r15b, r15x, ipl, iph,
                    bpl, bph, spl, sph;
        };
    };
} regs;

#define STEP(n) regs.rip += n;

void func(char* stack) {
    regs.al = 10;
    regs.eax = MEMORY_GET(uint32_t, regs.rbp+-4);
    regs.rbx = MEMORY_GET(uint64_t, regs.rbp+-32);
}

int main() {
}
```

