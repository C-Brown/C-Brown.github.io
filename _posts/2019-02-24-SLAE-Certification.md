---
layout: post
title: SLAE Certification
date:   2019-02-24
categories: [SLAE, Assembly]
---

I decided a while back that I wanted to go through PentesterAcademy's "x86 Assembly Language and Shellcoding in Linux" course for a 2nd time.  Except this time around I wanted to go for the SLAE certification.  I have been casually studying reverse engineering for years through various CTFs and for fun so, I figured this would be a good next step.  The next goal in the future would be to get OSCE.  

The certification is split up in to 7 questions of varying difficuly and involve writing x86 Linux assembly that is used to create shellcode for the solution.  So the questions are as follows:
### 1. Shell Bind TCP
* Binds to a port
* Executes a shell on successful connection
* The port should be easily configurable

### 2. Shell Reverse TCP
* Connects out (reverse) to a configured IP and Port
* Executes a shell on successful connection
* The IP and port should be easily configurable

### 3. Egg Hunter Shellcode
* Study Egg Hunter Shellcode
* Create a working demo
* Should be configuratble to different payloads

### 4. Custom Encoder
* Create a custom encoding scheme similar to the "Insertion Encoder"
* Provide a PoC with the execve-stack payload as the shellcode and execute

### 5. Metasploit Shellcode Analysis
* Analyze 3 different Metasploit linux/x86 payloads

### 6. Polymorphism
* Take up 3 shellcode samples from Shell-Storm and create a polymorphic version of them to beat pattern matching
* The polymorphic versions cannot be more than 150% the size of the original shellcode
* Bonus points awarded for making it shorter than the original

### 7. Custom Crypter
* Create a custom crypter like the one shown in the crypters video
* Free to use any existing encryption schema
* Can use any programming language

The course was really easy to follow and really built upon itself well so that each new topic seemed to be a smooth transition for me.  The idea of having my exam answers posted publically was a bit intimidating at first but now I feel like I would enjoy doing some extra research for my own entertainment and continuing to add to this blog after the exam.  

Overall it took me about 3 weeks of working in my spare time to get these questions finished but was well worth the effort.  I feel like I've learned a lot and become much more comfortable reading and writing x86 linux assembly.
