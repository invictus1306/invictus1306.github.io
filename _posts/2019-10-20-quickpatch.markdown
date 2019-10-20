---
layout: post
title:  "QuickPatch"
date:   2019-10-20
categories: vulnerabilities
---
# QuickPatch
[QuickPatch](https://github.com/invictus1306/QuickPatch) is mainly a GDB plug-in giving users the ability to patch an ELF file quickly, just by write the instructions to patch.

With *QuickPatch* is also possible to patch/disassemble a binary file for the architectures x86-32 x86-64 arm and arm64.   

It is based on [Capstone](https://www.capstone-engine.org/) and [Keystone](http://www.keystone-engine.org/).

Here we will see how to use the software with a very simple example.

This is the source of the file that we are going to analyze:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASSWORD "patch_me"
#define SIZE 256

int main(void) {
    char buffer[SIZE];

    printf("Password: ");

    fgets(buffer, SIZE, stdin);

    if (strncmp(buffer, PASSWORD, strlen(buffer)-1) == 0) {
        printf("Password correct!\n");
        return 0;
    }
    printf("Password incorrect!\n");

    return 0;
}
```

Compile it:
```shell
$ gcc -o patch_me_pie -fpie -pie patch_me.c
checksec patch_me_pie
[*] '/home/andrea/patch/tests/patch_me_pie'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

It is a very simple program, and we want to see the message "Password correct!" for any user password, for that purpose we have to patch it.

## Patch the binary with GDB
```shell
$ gdb ./tests/patch_me_pie
gdb> source gdbQuickPatch.py
gdb> b main
gdb> run
gdb> disassemble main

Dump of assembler code for function main:
   0x0000555555554920 <+0>:	push   rbp
   0x0000555555554921 <+1>:	mov    rbp,rsp
=> 0x0000555555554924 <+4>:	sub    rsp,0x110
   0x000055555555492b <+11>:	mov    rax,QWORD PTR fs:0x28
   0x0000555555554934 <+20>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000555555554938 <+24>:	xor    eax,eax
   0x000055555555493a <+26>:	lea    rdi,[rip+0x113]        # 0x555555554a54
   0x0000555555554941 <+33>:	mov    eax,0x0
   0x0000555555554946 <+38>:	call   0x5555555547b0 <printf@plt>
   0x000055555555494b <+43>:	mov    rdx,QWORD PTR [rip+0x20070e]        # 0x555555755060 <stdin@@GLIBC_2.2.5>
   0x0000555555554952 <+50>:	lea    rax,[rbp-0x110]
   0x0000555555554959 <+57>:	mov    esi,0x100
   0x000055555555495e <+62>:	mov    rdi,rax
   0x0000555555554961 <+65>:	call   0x5555555547d0 <fgets@plt>
   0x0000555555554966 <+70>:	lea    rax,[rbp-0x110]
   0x000055555555496d <+77>:	mov    rdi,rax
   0x0000555555554970 <+80>:	call   0x555555554790 <strlen@plt>
   0x0000555555554975 <+85>:	lea    rdx,[rax-0x1]
   0x0000555555554979 <+89>:	lea    rax,[rbp-0x110]
   0x0000555555554980 <+96>:	lea    rsi,[rip+0xd8]        # 0x555555554a5f
   0x0000555555554987 <+103>:	mov    rdi,rax
   0x000055555555498a <+106>:	call   0x555555554770 <strncmp@plt>
   0x000055555555498f <+111>:	test   eax,eax
   0x0000555555554991 <+113>:	jne    0x5555555549a6 <main+134>
   0x0000555555554993 <+115>:	lea    rdi,[rip+0xce]        # 0x555555554a68
   0x000055555555499a <+122>:	call   0x555555554780 <puts@plt>
   0x000055555555499f <+127>:	mov    eax,0x0
   0x00005555555549a4 <+132>:	jmp    0x5555555549b7 <main+151>
   0x00005555555549a6 <+134>:	lea    rdi,[rip+0xcd]        # 0x555555554a7a
   0x00005555555549ad <+141>:	call   0x555555554780 <puts@plt>
   0x00005555555549b2 <+146>:	mov    eax,0x0
   0x00005555555549b7 <+151>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x00005555555549bb <+155>:	xor    rcx,QWORD PTR fs:0x28
   0x00005555555549c4 <+164>:	je     0x5555555549cb <main+171>
   0x00005555555549c6 <+166>:	call   0x5555555547a0 <__stack_chk_fail@plt>
   0x00005555555549cb <+171>:	leave
   0x00005555555549cc <+172>:	ret
```

we want to patch the instruction at `0x000055555555498f` and the instruction at `0x0000555555554991` with *nops* instructions.

Let's get the *nop* opcode for the specific architecture:

```shell
gdb> get_bytes "nop"
[*] get_bytes command is called
-----------------------------------------------------
[*] Arch is i386:x86-64
[*] Instructions: ['nop'] (len: 1)
[*] Encoding: 0x90 (len: 1)
```

The length of the *nop* instruction is one byte (architecture is *i386:x86-64*), so we will need to use it 4 times in order to patch 4 bytes.

We try to patch it in not persistent mode in order, in order to verify if everything works fine:

```shell
gdb> memory_patch "nop;nop;nop;nop" 0x000055555555498f
[*] memory_patch command is called
-----------------------------------------------------
[*] Arch is i386:x86-64
[*] Instructions: ['nop', 'nop', 'nop', 'nop'] (len: 4)
[*] Encoding: 0x90 0x90 0x90 0x90 (len: 4)
[*] Memory is successfully patched at address 0x000055555555498f
```

Let's look the disassembly again:
```shell
gdb> disassemble main
Dump of assembler code for function main:
   0x0000555555554920 <+0>:	push   rbp
   0x0000555555554921 <+1>:	mov    rbp,rsp
=> 0x0000555555554924 <+4>:	sub    rsp,0x110
   0x000055555555492b <+11>:	mov    rax,QWORD PTR fs:0x28
   0x0000555555554934 <+20>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000555555554938 <+24>:	xor    eax,eax
   0x000055555555493a <+26>:	lea    rdi,[rip+0x113]        # 0x555555554a54
   0x0000555555554941 <+33>:	mov    eax,0x0
   0x0000555555554946 <+38>:	call   0x5555555547b0 <printf@plt>
   0x000055555555494b <+43>:	mov    rdx,QWORD PTR [rip+0x20070e]        # 0x555555755060 <stdin@@GLIBC_2.2.5>
   0x0000555555554952 <+50>:	lea    rax,[rbp-0x110]
   0x0000555555554959 <+57>:	mov    esi,0x100
   0x000055555555495e <+62>:	mov    rdi,rax
   0x0000555555554961 <+65>:	call   0x5555555547d0 <fgets@plt>
   0x0000555555554966 <+70>:	lea    rax,[rbp-0x110]
   0x000055555555496d <+77>:	mov    rdi,rax
   0x0000555555554970 <+80>:	call   0x555555554790 <strlen@plt>
   0x0000555555554975 <+85>:	lea    rdx,[rax-0x1]
   0x0000555555554979 <+89>:	lea    rax,[rbp-0x110]
   0x0000555555554980 <+96>:	lea    rsi,[rip+0xd8]        # 0x555555554a5f
   0x0000555555554987 <+103>:	mov    rdi,rax
   0x000055555555498a <+106>:	call   0x555555554770 <strncmp@plt>
   0x000055555555498f <+111>:	nop
   0x0000555555554990 <+112>:	nop
   0x0000555555554991 <+113>:	nop
   0x0000555555554992 <+114>:	nop
   0x0000555555554993 <+115>:	lea    rdi,[rip+0xce]        # 0x555555554a68
   0x000055555555499a <+122>:	call   0x555555554780 <puts@plt>
   0x000055555555499f <+127>:	mov    eax,0x0
   0x00005555555549a4 <+132>:	jmp    0x5555555549b7 <main+151>
   0x00005555555549a6 <+134>:	lea    rdi,[rip+0xcd]        # 0x555555554a7a
   0x00005555555549ad <+141>:	call   0x555555554780 <puts@plt>
   0x00005555555549b2 <+146>:	mov    eax,0x0
   0x00005555555549b7 <+151>:	mov    rcx,QWORD PTR [rbp-0x8]
   0x00005555555549bb <+155>:	xor    rcx,QWORD PTR fs:0x28
   0x00005555555549c4 <+164>:	je     0x5555555549cb <main+171>
   0x00005555555549c6 <+166>:	call   0x5555555547a0 <__stack_chk_fail@plt>
   0x00005555555549cb <+171>:	leave
   0x00005555555549cc <+172>:	ret
```

We did well, so we can patch the program in a persistent way:

```shell
gdb> program_patch "nop;nop;nop;nop" 0x000055555555498f patch_me_with_patch
[*] program_patch command is called
-----------------------------------------------------
[*] Arch is i386:x86-64
[*] Address 0x555555554000 module name /home/invictus/Documents/QuickPatch/patch/tests/patch_me_pie address is 0x000055555555498f
[*] Offset is 0x98f
[*] Instructions: ['nop', 'nop', 'nop', 'nop'] (len: 4)
[*] Encoding: 0x90 0x90 0x90 0x90 (len: 4)
[*] File patch_me_with_patch with patch is created
```

Let's try it

```shell
$ ./patch_me_with_patch
Password: randomsasa
Password correct!
```

## Patch the binary without GDB
```shell
python3 QuickPatch.py -A x86-64 -a 'nop;nop;nop;nop' -o 0x98f -b ./tests/patch_me_pie -of patch_nogdb
[*] Instructions: ['nop', 'nop', 'nop', 'nop'] (len: 4)
[*] Encoding: 0x90 0x90 0x90 0x90 (len: 4)
[*] File patch_nogdb with patch is created
```

Let's try it

```
$ ./patch_nogdb
Password: kkfskfsdk
Password correct!
```

Disassemble it before and after:
```shell
$ python3 QuickPatch.py -A x86-64 -o 0x98f -b ./tests/patch_me_pie -dl 5
0x98f: 85c0             test  eax, eax        
0x991: 7513             jne   0x9a6           
0x993: 488d3dce000000   lea   rdi, [rip + 0xce]
0x99a: e8e1fdffff       call  0x780           
0x99f: b800000000       mov   eax, 0

$ python3 QuickPatch.py -A x86-64 -o 0x98f -b ./patch_nogdb -dl 5
0x98f: 90               nop                   
0x990: 90               nop                   
0x991: 90               nop                   
0x992: 90               nop                   
0x993: 488d3dce000000   lea   rdi, [rip + 0xce]
```

## SHELLCODE
This other simple example will show how to disassemble from user input a shellcode.

For example for this [shellcode](http://shell-storm.org/shellcode/files/shellcode-603.php)

```shell
$ python3 QuickPatch.py -A x86-64 -d "0x48,0x31,0xd2,0x48,0xbb,0x2f,0x2f,0x62,0x69,0x6e,0x2f,0x73,0x68,0x48,0xc1,0xeb,0x08,0x53,0x48,0x89,0xe7,0x50,0x57,0x48,0x89,0xe6,0xb0,0x3b,0x0f,0x05"
0x0: 4831d2           xor   rdx, rdx
0x3: 48bb2f2f62696e2f7368 movabs rbx, 0x68732f6e69622f2f
0xd: 48c1eb08         shr   rbx, 8
0x11: 53               push  rbx
0x12: 4889e7           mov   rdi, rsp
0x15: 50               push  rax
0x16: 57               push  rdi
0x17: 4889e6           mov   rsi, rsp
0x1a: b03b             mov   al, 0x3b
0x1c: 0f05             syscall
```
