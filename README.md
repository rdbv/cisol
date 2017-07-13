# cisol - C isolation tool
---
# Introduction
Mini tool to translating fragments of x86 asm to C code.

When i was doing CTF task, i rewritten a large part of program because i wanted to understand how it works (and write a keygen, ofc).
Rewritting code, instruction by instruction took too long time.

So i thinked about this simple tool, that might be useful for CTF's.
For now, is definitely not useful for anything, and supports only basic instructions.
Feel free to contribute! :) 
---
# Simple example

```
int main() {
    char a[4] = {1, 2, 3, 4};
    unsigned int sum = 0;
    for(unsigned char i=0;i<4;++i)
        sum += a[i];
    printf("%d\n", sum);
}
```
### Dump of main. (From radare2)

```
    ;-- main:                                                    
        0x00000710      55             push rbp
        0x00000711      4889e5         mov rbp, rsp
        0x00000714      4883ec20       sub rsp, 0x20
        0x00000718      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=0x19d8 ; '('
        0x00000721      488945f8       mov qword [rbp - 8], rax
        0x00000725      31c0           xor eax, eax
        0x00000727      c645f401       mov byte [rbp - 0xc], 1
        0x0000072b      c645f502       mov byte [rbp - 0xb], 2
        0x0000072f      c645f603       mov byte [rbp - 0xa], 3
        0x00000733      c645f704       mov byte [rbp - 9], 4
        0x00000737      c745f0000000.  mov dword [rbp - 0x10], 0
        0x0000073e      c645ef00       mov byte [rbp - 0x11], 0
    ,=< 0x00000742      eb15           jmp 0x759                   ;[1]
   .--> 0x00000744      0fb645ef       movzx eax, byte [rbp - 0x11]
   ||   0x00000748      4898           cdqe
   ||   0x0000074a      0fb64405f4     movzx eax, byte [rbp + rax - 0xc]
   ||   0x0000074f      0fbec0         movsx eax, al
   ||   0x00000752      0145f0         add dword [rbp - 0x10], eax
   ||   0x00000755      8045ef01       add byte [rbp - 0x11], 1
   |`-> 0x00000759      807def03       cmp byte [rbp - 0x11], 3    ; [0x3:1]=70
   `==< 0x0000075d      76e5           jbe 0x744                   ;[2]
        0x0000075f      8b45f0         mov eax, dword [rbp - 0x10]
        0x00000762      89c6           mov esi, eax
        0x00000764      488d3da90000.  lea rdi, 0x00000814         ; "%d\n"
        0x0000076b      b800000000     mov eax, 0
        0x00000770      e853feffff     call sym.imp.printf         ;[3]
        0x00000775      b800000000     mov eax, 0
        0x0000077a      488b55f8       mov rdx, qword [rbp - 8]
        0x0000077e      644833142528.  xor rdx, qword fs:[0x28]
    ,=< 0x00000787      7405           je 0x78e                    ;[4]
    |   0x00000789      e832feffff     call sym.imp.__stack_chk_fail ;[5]
    `-> 0x0000078e      c9             leave
        0x0000078f      c3             ret
```
### Finally, cisol translate this code (in range 0x727-0x760) to equivalent C code
```./cisol.py -f bin/main -o out.c -b 0x727 -e 0x760```
```
void func() {
    MEMORY(uint8_t, rbp-12) = 1; // mov byte ptr [rbp - 0xc], 1
    MEMORY(uint8_t, rbp-11) = 2; // mov byte ptr [rbp - 0xb], 2
    MEMORY(uint8_t, rbp-10) = 3; // mov byte ptr [rbp - 0xa], 3
    MEMORY(uint8_t, rbp-9) = 4; // mov byte ptr [rbp - 9], 4
    MEMORY(uint32_t, rbp-16) = 0; // mov dword ptr [rbp - 0x10], 0
    MEMORY(uint8_t, rbp-17) = 0; // mov byte ptr [rbp - 0x11], 0
    goto _32; // jmp 0x32
_1d:; 
    rbx = 0, eax = MEMORY(uint8_t, rbp-17); // movzx eax, byte ptr [rbp - 0x11]
    // cdqe not implemented yet; 
    rbx = 0, eax = MEMORY(uint8_t, rbp+rax*1-12); // movzx eax, byte ptr [rbp + rax - 0xc]
    rbx = 0, eax = al; // movsx eax, al
    TMP32(MEMORY(uint32_t, rbp-16), +, eax); // add dword ptr [rbp - 0x10], eax
      SET_CF_ADD(32, MEMORY(uint32_t, rbp-16));
      SET_ZF(32);
      SET_AF_0(MEMORY(uint8_t, rbp-16), al);
      SET_OF_ADD(MEMORY(uint32_t, rbp-16), eax, 32, 0x80000000);
        MEMORY(uint32_t, rbp-16) = tmp32;
    TMP8(MEMORY(uint8_t, rbp-17), +, 1); // add byte ptr [rbp - 0x11], 1
      SET_CF_ADD(8, MEMORY(uint8_t, rbp-17));
      SET_ZF(8);
      SET_AF_0(MEMORY(uint8_t, rbp-17), 1);
      SET_OF_ADD(MEMORY(uint8_t, rbp-17), 1, 8, 0x80);
        MEMORY(uint8_t, rbp-17) = tmp8;
_32:; 
    TMP8(MEMORY(uint8_t, rbp-17), -, 3); // cmp byte ptr [rbp - 0x11], 3
      SET_CF_SUB(MEMORY(uint8_t, rbp-17), 3);
      SET_ZF(8);
      SET_AF_0(MEMORY(uint8_t, rbp-17), 3);
      SET_OF_SUB(MEMORY(uint8_t, rbp-17), 3, 8, 0x80);
    if(cf == 1 || zf == 1)
      goto _1d; // jbe 0x1d
}

int main() {
    rbp = 20;
    // here we set env (regs, memory)
    func();
    // sum is 10
    printf("%d\n", MEMORY(uint8_t, rbp-0x10));
}

```

