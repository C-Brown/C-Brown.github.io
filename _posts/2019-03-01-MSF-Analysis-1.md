---
layout: post
title: SLAE 5.1 - Metasploit Payload Analysis Exec
date:   2019-03-01
categories: [SLAE, Assembly]
---
The first metasploit payload for linux x86 that we will analyze will be:

linux/x86/exec

We will set the payload up to execute the ls command:

msfvenom -p linux/x86/exec CMD=ls -f c

[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload

[-] No arch selected, selecting arch: x86 from the payload

No encoder or badchars specified, outputting raw payload

Payload size: 38 bytes

Final size of c file: 185 bytes

unsigned char buf[] = 

"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x63\x89\xe7\x68\x2f\x73\x68"

"\x00\x68\x2f\x62\x69\x6e\x89\xe3\x52\xe8\x03\x00\x00\x00\x6c"

"\x73\x00\x57\x53\x89\xe1\xcd\x80";


Lets verify that this works.. If you'd like to see the steps for using a c wrapper and compiling options to test shellcode, feel free to take a look at the first 2 posts for my SLAE solutions, Shell Bind TCP and Shell Reverse TCP.

Place the shellcode into the c wrapper and compile it with the proper options.

Run it.. 
```shell
~/SLAE$ ./exam_docs/shellcode2 
Shellcode Length:  15
Arithmetic  Logical	command_line_get_shellcode_objdump.txt	execve		   execve.o		   hello_world_shell.o	   libc_practice       shellcode.c
Control     MovingData	compile.sh				execve-stack	   gcc_shellcode.txt	   hello_world_stack	   libc_practice.nasm  syscall_args.txt
DataTypes   Procedure	compile_gcc.sh				execve-stack.nasm  hello_World		   hello_world_stack.nasm  libc_practice.o     template
HelloWorld  Shellcode	compile_link.txt			execve-stack.o	   hello_world_shell	   hello_world_stack.o	   libc_reqs.txt       template.nasm
Libc	    Strings	exam_docs				execve.nasm	   hello_world_shell.nasm  ia32_includes.txt	   shellcode	       template.o
```
Looks like it works, let's begin our analysis.

To begin I will run gdb with our wrapper. Let's check where our shellcode is called.
> set disassembly-flavor intel

> disass main

```nasm
gdb-peda$ set disassembly-flavor intel
gdb-peda$ disass main
Dump of assembler code for function main:
   0x0804843b <+0>:	lea    ecx,[esp+0x4]
   0x0804843f <+4>:	and    esp,0xfffffff0
   0x08048442 <+7>:	push   DWORD PTR [ecx-0x4]
   0x08048445 <+10>:	push   ebp
   0x08048446 <+11>:	mov    ebp,esp
   0x08048448 <+13>:	push   ecx
   0x08048449 <+14>:	sub    esp,0x14
   0x0804844c <+17>:	sub    esp,0xc
   0x0804844f <+20>:	push   0x804a040
   0x08048454 <+25>:	call   0x8048310 <strlen@plt>
   0x08048459 <+30>:	add    esp,0x10
   0x0804845c <+33>:	sub    esp,0x8
   0x0804845f <+36>:	push   eax
   0x08048460 <+37>:	push   0x8048510
   0x08048465 <+42>:	call   0x8048300 <printf@plt>
   0x0804846a <+47>:	add    esp,0x10
   0x0804846d <+50>:	mov    DWORD PTR [ebp-0xc],0x804a040
   0x08048474 <+57>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048477 <+60>:	call   eax
   0x08048479 <+62>:	mov    eax,0x0
   0x0804847e <+67>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x08048481 <+70>:	leave  
   0x08048482 <+71>:	lea    esp,[ecx-0x4]
   0x08048485 <+74>:	ret    
End of assembler dump.
gdb-peda$ 
```
We can see the "call eax" instruction at 0x08048477, which is where our shellcode is called. Let's set a breakpoint there and step in.
```nasm
gdb-peda$ break *0x08048477
Breakpoint 1 at 0x8048477
gdb-peda$ r
Starting program: /home/pwoer/SLAE/exam_docs/shellcode2 
Shellcode Length:  15

[----------------------------------registers-----------------------------------]
EAX: 0x804a040 --> 0x99580b6a 
EBX: 0x0 
ECX: 0x7fffffea 
EDX: 0xb7fba870 --> 0x0 
ESI: 0xb7fb9000 --> 0x1b1db0 
EDI: 0xb7fb9000 --> 0x1b1db0 
EBP: 0xbfffeff8 --> 0x0 
ESP: 0xbfffefe0 --> 0x1 
EIP: 0x8048477 (<main+60>:	call   eax)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804846a <main+47>:	add    esp,0x10
   0x804846d <main+50>:	mov    DWORD PTR [ebp-0xc],0x804a040
   0x8048474 <main+57>:	mov    eax,DWORD PTR [ebp-0xc]
=> 0x8048477 <main+60>:	call   eax
   0x8048479 <main+62>:	mov    eax,0x0
   0x804847e <main+67>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x8048481 <main+70>:	leave  
   0x8048482 <main+71>:	lea    esp,[ecx-0x4]
No argument
[------------------------------------stack-------------------------------------]
0000| 0xbfffefe0 --> 0x1 
0004| 0xbfffefe4 --> 0xbffff0a4 --> 0xbffff28a ("/home/pwoer/SLAE/exam_docs/shellcode2")
0008| 0xbfffefe8 --> 0xbffff0ac --> 0xbffff2b0 ("XDG_VTNR=7")
0012| 0xbfffefec --> 0x804a040 --> 0x99580b6a 
0016| 0xbfffeff0 --> 0xb7fb93dc --> 0xb7fba1e0 --> 0x0 
0020| 0xbfffeff4 --> 0xbffff010 --> 0x1 
0024| 0xbfffeff8 --> 0x0 
0028| 0xbfffeffc --> 0xb7e1f637 (<__libc_start_main+247>:	add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048477 in main ()
gdb-peda$ si
```
Lets disassemble this function to see what we are working through.
```nasm
gdb-peda$ disass &code
Dump of assembler code for function code:
   0x0804a040 <+0>:	push   0xb
   0x0804a042 <+2>:	pop    eax
   0x0804a043 <+3>:	cdq    
   0x0804a044 <+4>:	push   edx
   0x0804a045 <+5>:	pushw  0x632d
   0x0804a049 <+9>:	mov    edi,esp
   0x0804a04b <+11>:	push   0x68732f
   0x0804a050 <+16>:	push   0x6e69622f
   0x0804a055 <+21>:	mov    ebx,esp
   0x0804a057 <+23>:	push   edx
   0x0804a058 <+24>:	call   0x804a060 <code+32>
   0x0804a05d <+29>:	ins    BYTE PTR es:[edi],dx
   0x0804a05e <+30>:	jae    0x804a060 <code+32>
   0x0804a060 <+32>:	push   edi
   0x0804a061 <+33>:	push   ebx
   0x0804a062 <+34>:	mov    ecx,esp
   0x0804a064 <+36>:	int    0x80
   0x0804a066 <+38>:	add    BYTE PTR [eax],al
End of assembler dump.
```
Our point of interest is the syscall at 0x0804a064.

We can step through to watch how the syscall is set up.
```nasm
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0x0 
ECX: 0x7fffffea 
EDX: 0xb7fba870 --> 0x0 
ESI: 0xb7fb9000 --> 0x1b1db0 
EDI: 0xb7fb9000 --> 0x1b1db0 
EBP: 0xbfffeff8 --> 0x0 
ESP: 0xbfffefdc --> 0x8048479 (<main+62>:	mov    eax,0x0)
EIP: 0x804a043 --> 0x68665299
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a03d:	add    BYTE PTR [eax],al
   0x804a03f:	add    BYTE PTR [edx+0xb],ch
   0x804a042 <code+2>:	pop    eax
=> 0x804a043 <code+3>:	cdq    
   0x804a044 <code+4>:	push   edx
   0x804a045 <code+5>:	pushw  0x632d
   0x804a049 <code+9>:	mov    edi,esp
   0x804a04b <code+11>:	push   0x68732f
[------------------------------------stack-------------------------------------]
0000| 0xbfffefdc --> 0x8048479 (<main+62>:	mov    eax,0x0)
0004| 0xbfffefe0 --> 0x1 
0008| 0xbfffefe4 --> 0xbffff0a4 --> 0xbffff28a ("/home/pwoer/SLAE/exam_docs/shellcode2")
0012| 0xbfffefe8 --> 0xbffff0ac --> 0xbffff2b0 ("XDG_VTNR=7")
0016| 0xbfffefec --> 0x804a040 --> 0x99580b6a 
0020| 0xbfffeff0 --> 0xb7fb93dc --> 0xb7fba1e0 --> 0x0 
0024| 0xbfffeff4 --> 0xbffff010 --> 0x1 
0028| 0xbfffeff8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a043 in code ()
gdb-peda$
```
push byte 0xb

pop eax

EAX will be the syscall number -> 0xb means that we are calling execve
```c
int execve(const char *filename, char *const argv[], char *const envp[]);
```
Our next instructions:
```nasm
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0x0 
ECX: 0x7fffffea 
EDX: 0x0 
ESI: 0xb7fb9000 --> 0x1b1db0 
EDI: 0xbfffefd6 --> 0x632d ('-c')
EBP: 0xbfffeff8 --> 0x0 
ESP: 0xbfffefd6 --> 0x632d ('-c')
EIP: 0x804a04b ("h/sh")
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a044 <code+4>:	push   edx
   0x804a045 <code+5>:	pushw  0x632d
   0x804a049 <code+9>:	mov    edi,esp
=> 0x804a04b <code+11>:	push   0x68732f
   0x804a050 <code+16>:	push   0x6e69622f
   0x804a055 <code+21>:	mov    ebx,esp
   0x804a057 <code+23>:	push   edx
   0x804a058 <code+24>:	call   0x804a060 <code+32>
[------------------------------------stack-------------------------------------]
0000| 0xbfffefd6 --> 0x632d ('-c')
0004| 0xbfffefda --> 0x84790000 
0008| 0xbfffefde --> 0x10804 
0012| 0xbfffefe2 --> 0xf0a40000 
0016| 0xbfffefe6 --> 0xf0acbfff 
0020| 0xbfffefea --> 0xa040bfff 
0024| 0xbfffefee --> 0x93dc0804 
0028| 0xbfffeff2 --> 0xf010b7fb 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a04b in code ()
gdb-peda$ 
```
cdq

push edx

pushw 0x632d

mov edi, esp

This block of instructions is preparing the arguments for the syscall.

cdq zero's out edx, then we push it to the stack preparing a null terminated string.

pushw 0x632d is pushing '-c' to the stack which is our argument for the command and will go in argv\[\].

mov edi, esp is storing the address for this part of the arguments.  We will come back to edi in a bit when we are setting up ECX.
```nasm
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbfffefce ("/bin/sh")
ECX: 0x7fffffea 
EDX: 0x0 
ESI: 0xb7fb9000 --> 0x1b1db0 
EDI: 0xbfffefd6 --> 0x632d ('-c')
EBP: 0xbfffeff8 --> 0x0 
ESP: 0xbfffefce ("/bin/sh")
EIP: 0x804a057 --> 0x3e852
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a04b <code+11>:	push   0x68732f
   0x804a050 <code+16>:	push   0x6e69622f
   0x804a055 <code+21>:	mov    ebx,esp
=> 0x804a057 <code+23>:	push   edx
   0x804a058 <code+24>:	call   0x804a060 <code+32>
   0x804a05d <code+29>:	ins    BYTE PTR es:[edi],dx
   0x804a05e <code+30>:	jae    0x804a060 <code+32>
   0x804a060 <code+32>:	push   edi
[------------------------------------stack-------------------------------------]
0000| 0xbfffefce ("/bin/sh")
0004| 0xbfffefd2 --> 0x68732f ('/sh')
0008| 0xbfffefd6 --> 0x632d ('-c')
0012| 0xbfffefda --> 0x84790000 
0016| 0xbfffefde --> 0x10804 
0020| 0xbfffefe2 --> 0xf0a40000 
0024| 0xbfffefe6 --> 0xf0acbfff 
0028| 0xbfffefea --> 0xa040bfff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a057 in code ()
gdb-peda$
```
push 0x68732f

push 0x6e69622f

These two push instructions are pushing '/bin/sh' to the stack

mov ebx, esp sets our first argument for execve.. filename will be '/bin/sh'
```nasm
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbfffefce ("/bin/sh")
ECX: 0x7fffffea 
EDX: 0x0 
ESI: 0xb7fb9000 --> 0x1b1db0 
EDI: 0xbfffefd6 --> 0x632d ('-c')
EBP: 0xbfffeff8 --> 0x0 
ESP: 0xbfffefca --> 0x0 
EIP: 0x804a058 --> 0x3e8
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a050 <code+16>:	push   0x6e69622f
   0x804a055 <code+21>:	mov    ebx,esp
   0x804a057 <code+23>:	push   edx
=> 0x804a058 <code+24>:	call   0x804a060 <code+32>
   0x804a05d <code+29>:	ins    BYTE PTR es:[edi],dx
   0x804a05e <code+30>:	jae    0x804a060 <code+32>
   0x804a060 <code+32>:	push   edi
   0x804a061 <code+33>:	push   ebx
Guessed arguments:
arg[0]: 0x0 
arg[1]: 0x6e69622f ('/bin')
arg[2]: 0x68732f ('/sh')
arg[3]: 0x632d ('-c')
arg[4]: 0x84790000 
[------------------------------------stack-------------------------------------]
0000| 0xbfffefca --> 0x0 
0004| 0xbfffefce ("/bin/sh")
0008| 0xbfffefd2 --> 0x68732f ('/sh')
0012| 0xbfffefd6 --> 0x632d ('-c')
0016| 0xbfffefda --> 0x84790000 
0020| 0xbfffefde --> 0x10804 
0024| 0xbfffefe2 --> 0xf0a40000 
0028| 0xbfffefe6 --> 0xf0acbfff 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a058 in code ()
gdb-peda$
```
push edx pushes our null byte to the stack

call 0x804a060 is where our shellcoding tricks kick in.  It is similar to the jmp-call-pop technique, but we are just calling an address in order to push the next address to the stack (0x804a05d).

When we check what is at that address, we see - 
```shell
gdb-peda$ x/x 0x804a05d
0x804a05d <code+29>:	0x5700736c
```
Little Endian here -- this gives us 6c7300 -> null terminated 'ls' which is the command we used to create this shellcode.

Looking at our code, we know the next address following our string will be the opcode for 'push edi'.  Let's check to make sure.. the byte following our string is 57 --
```shell
nasm> disas
disas mode
ndisasm> 57
57                       push edi
```
Looks like we are on the right track!
```nasm
[----------------------------------registers-----------------------------------]
EAX: 0xb ('\x0b')
EBX: 0xbfffefce ("/bin/sh")
ECX: 0xbfffefbe --> 0xbfffefce ("/bin/sh")
EDX: 0x0 
ESI: 0xb7fb9000 --> 0x1b1db0 
EDI: 0xbfffefd6 --> 0x632d ('-c')
EBP: 0xbfffeff8 --> 0x0 
ESP: 0xbfffefbe --> 0xbfffefce ("/bin/sh")
EIP: 0x804a064 --> 0x80cd
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804a060 <code+32>:	push   edi
   0x804a061 <code+33>:	push   ebx
   0x804a062 <code+34>:	mov    ecx,esp
=> 0x804a064 <code+36>:	int    0x80
   0x804a066 <code+38>:	add    BYTE PTR [eax],al
   0x804a068:	add    BYTE PTR [eax],al
   0x804a06a:	add    BYTE PTR [eax],al
   0x804a06c:	add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xbfffefbe --> 0xbfffefce ("/bin/sh")
0004| 0xbfffefc2 --> 0xbfffefd6 --> 0x632d ('-c')
0008| 0xbfffefc6 --> 0x804a05d --> 0x5700736c ('ls')
0012| 0xbfffefca --> 0x0 
0016| 0xbfffefce ("/bin/sh")
0020| 0xbfffefd2 --> 0x68732f ('/sh')
0024| 0xbfffefd6 --> 0x632d ('-c')
0028| 0xbfffefda --> 0x84790000 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x0804a064 in code ()
gdb-peda$
```
push edi

push ebx

mov ecx, esp

int 0x80

EDI was set earlier as a pointer to an address on the stack for the '-c' string.  We push that on the stack so we currently have '-c ls'

EBX contains our pointer to an address on the stack for the '/bin/sh' string.  We push that on the stack so we now have '/bin/sh -c ls'

'mov ecx, esp' moves the current stack pointer into ECX so our 2nd argument for execve now holds the proper arguments that we want it to use.

int 0x80 - this launches our execve call -> execve('/bin/sh', '/bin/sh -c ls', 0);
