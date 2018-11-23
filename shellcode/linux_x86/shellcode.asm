[SECTION .text]
global _start
_start:
	push 0x0068732f
	push 0x6e69622f
	mov ebx, esp
	xor edx, edx
	push ebx
	push edx
	mov ecx, esp
	mov eax, 0xb
	int 0x80
