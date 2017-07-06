main_asm:
	nasm -f elf64 bin/main_asm.asm -o bin/main_asm.o
	ld bin/main_asm.o -o bin/main
