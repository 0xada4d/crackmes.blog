---
draft: false 
date: 2024-02-15 
categories:
  - Reverse Engineering
tags:
  - x86_64
  - crackmes.one
slug: game-crackme
---

# RE Challenge: nuts9753's game crackme [on crackmes.one](https://crackmes.one/crackme/65adde2aeef082e477ff5f56) 

***

### Binary 

```
Name: gameCrackme.exe
Application Type: Windows(Vista)[AMD64, 64-bit, Console]
```

```cmd
$ .\gameCrackme.exe
Enter the activation key: test
The key is incorrect.
```

<!-- more -->

***

### Analysis

We are given the information that the program begins by sending an HTTP request to a local server  to perform a check of the activation code. The first step is to examine the network traffic. To do this, I will start the server, locate the local port it is listening on, then run Wireshark to capture the traffic. 

Send the key: (test)
```
GET /check%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00 HTTP/1.1
Host: 127.0.0.1
User-Agent: zig/0.11.0 (std.http)
Connection: keep-alive
Accept-Encoding: gzip, deflate, zstd
TE: gzip, deflate, trailers
key: test
```

Server response:
```
HTTP/1.1 200 OK
Connection: keep-alive
Transfer-Encoding: chunked
content-type: text/plain
server: crackme :3
session-id: 2293003546
...
false
0
```

The server sends a `false` response with a bad key. 

Opening the binary in IDA, we see the prompt for the activation key here:

```asm
.text:00007FF7681370AA                 lea     rdx, aEnterTheActiva ;
.text:00007FF7681370B1                 mov     r8d, 1Ah
.text:00007FF7681370B7                 call    sub_7FF768137CDC
```

And the subsequent capturing of user input (activation key) here: 

```asm
.text:00007FF7681370C7                 lea     r8, unk_7FF76817A658
.text:00007FF7681370CE                 lea     rsi, [rsp+108h+var_70]
.text:00007FF7681370D6                 lea     rdx, [rsp+108h+var_B0]
.text:00007FF7681370DB                 mov     rcx, rsi
.text:00007FF7681370DE                 call    sub_7FF768131000
```

The meat of the binary is located in function `sub_7FF768131CE9`. This section is complicated, with a ton of different paths the code can take. The most important bit that we need to keep track of is that this is where the HTTP client/server functionality resides. 

```asm
.text:00007FF768137120                 call    sub_7FF768131CE9
.text:00007FF768137125                 movzx   esi, word ptr [rsi]
.text:00007FF768137128                 test    si, si
.text:00007FF76813712B                 jnz     loc_7FF7681372EA
.text:00007FF768137131                 cmp     [rsp+108h+var_CE], 1
.text:00007FF768137136                 jnz     loc_7FF7681372C0
.text:00007FF76813713C                 mov     [rsp+108h+var_C0], r14
.text:00007FF768137141                 mov     [rsp+108h+var_B8], rbx
.text:00007FF768137146                 mov     rax, gs:30h
.text:00007FF76813714F                 mov     rax, [rax+60h]
.text:00007FF768137153                 mov     rax, [rax+20h]
.text:00007FF768137157                 mov     rdx, [rax+28h]
.text:00007FF76813715B                 mov     rax, gs:30h
.text:00007FF768137164                 mov     rax, [rax+60h]
.text:00007FF768137168                 mov     rax, [rax+20h]
.text:00007FF76813716C                 mov     rax, [rax+20h]
.text:00007FF768137170                 mov     [rsp+108h+var_A8], rax
.text:00007FF768137175                 lea     rcx, [rsp+108h+var_A0]
.text:00007FF76813717A                 mov     rdi, rdx
.text:00007FF76813717D                 mov     [rcx], rdx
.text:00007FF768137180                 lea     rdx, aCongratulation ;
.text:00007FF768137187                 mov     r8d, 137h
.text:00007FF76813718D                 call    sub_7FF768137CDC
```

Notice the check performed here:

```asm
.text:00007FF768137131                 cmp     [rsp+108h+var_CE], 1
```

If `rsp+108h+var_CE` equals 1, the function prints the success message, meaning the correct activation key was provided. Otherwise the activation key is incorrect, and the program exits with the message `The key is incorrect`. We can assume that this value is set during the operation of `sub_7FF768131CE9`. Too bad we can't patch and move on..

To analyze the HTTP functionality, I'll begin by finding references to the `false` string. Hopefully this gets us close to where the actual activation-key check occurs. The string has two cross references:

```asm
.rdata:00007FF76817CFBE aFalse          db 'false',0            ; DATA XREF: sub_7FF76814154E+41A9↑o
.rdata:00007FF76817CFBE                                         ; sub_7FF76814154E+4210↑o
```

The first reference `sub_7FF76814154E+41A9` looks the most interesting:

```asm
.text:00007FF7681456F0                 call    sub_7FF768136E44
.text:00007FF7681456F5                 test    al, 1
.text:00007FF7681456F7                 lea     rdx, aFalse     ; "false"
.text:00007FF7681456FE                 lea     rcx, aTrue      ; "true"
.text:00007FF768145705                 cmovnz  rdx, rcx
.text:00007FF768145709                 movzx   r8d, al
.text:00007FF76814570D                 and     r8d, 1
.text:00007FF768145711                 xor     r8, 5
.text:00007FF768145715                 lea     rcx, [rsp+40h+arg_16A8]
.text:00007FF76814571D                 call    sub_7FF7681413F7
```

If the return value of `sub_7FF768136E44` is 1 (al = 1), the `true` message is passed to `sub_7FF7681413F7`. Otherwise the `false` message is passed. 

I'll put a breakpoint on `sub_7FF768136E44` and run the code in the debugger to see what values are passed to the function. 

```asm
.text:00007FF7681456CB                 test    rax, rax
.text:00007FF7681456CE                 cmovz   rdx, rax
.text:00007FF7681456D2                 mov     rcx, rax
.text:00007FF7681456D5                 lea     rax, unk_7FF7681912D3
.text:00007FF7681456DC                 cmovz   rcx, rax
.text:00007FF7681456E0                 mov     r8, [rsp+40h+arg_1B0]
.text:00007FF7681456E8                 mov     r9, [rsp+40h+arg_1B8]
.text:00007FF7681456F0                 call    sub_7FF768136E44

->

rdx = 4
rcx = test
r8 = [rsp+40h+arg_1B0] = 4235971581
r9 = [rsp+40h+arg_1B8] = 10 (decimal)
```

 I entered "test" as the activation code in the terminal. It looks as if the function takes two strings and their lengths as input (4 parameters), probably for comparison purposes. Checking the disassembly for `sub_7FF768136E44` confirms our suspicions:

```asm
.text:00007FF768136E44                 cmp     rdx, r9
.text:00007FF768136E47                 jnz     short loc_7FF768136E6B
.text:00007FF768136E49                 cmp     rcx, r8
.text:00007FF768136E4C                 jz      short loc_7FF768136E6E
.text:00007FF768136E4E                 xor     r9d, r9d
...
.text:00007FF768136E51                 cmp     rdx, r9
.text:00007FF768136E54                 setz    al
.text:00007FF768136E57                 jz      short locret_7FF768136E6A
.text:00007FF768136E59                 mov     r10b, [rcx+r9]
.text:00007FF768136E5D                 lea     r11, [r9+1]
.text:00007FF768136E61                 cmp     r10b, [r8+r9]
.text:00007FF768136E65                 mov     r9, r11
.text:00007FF768136E68                 jz      short loc_7FF768136E51
```

First the string lengths are compared; if they are not equal, the function returns 0. If the lengths are equal, the function then compares each byte of each string. If they match, the function returns 1. Since one parameter to this function was the input string, we can assume that the activation key is the other (4235971581).

Let's test this value. 

Tracing the instructions back further, we find `r8` loaded with the value of the key here:

```asm
.text:00007FF768137B0F                 call    sub_7FF76813CFD8
.text:00007FF768137B14                 mov     r8, [rsp+2E8h+var_2B0]
.text:00007FF768137B19                 mov     r9, [rsp+2E8h+var_2A0]
```

`sub_7FF76813CFD8` sets `rsp+2E8h+var_2B0` with the value of the key, which is then loaded into `r8` and subsequently passed to the comparison function. Set a breakpoint on `00007FF768137B19` then run the debugger and grab the value to input into the activation key prompt:

```
Enter the activation key: 127099870
Congratulations! The key is correct.
Now to finish the crackme you need to complete the game and find the code.
Imagine that you are in a room with two code panels and a door. To open the door you need to find two codes.
Enter the codes in the "code1, code2" format
--------------------------------------------
Enter the codes:
```

The key works. Now the game begins, and requests two codes. Following the disassembly in the `start` routine, we see two candidates for codes:

```asm
.text:00007FF76813727D                 lea     r8, aCode1f019  ; "code@1F019"
.text:00007FF768137284                 call    sub_7FF768136E44
.text:00007FF768137289                 test    al, 1
.text:00007FF76813728B                 jz      short loc_7FF7681372AD
.text:00007FF76813728D                 mov     r9d, 16h
.text:00007FF768137293                 mov     rcx, rsi
.text:00007FF768137296                 mov     rdx, r12
.text:00007FF768137299                 lea     r8, aCode0011101000 ;
.text:00007FF7681372A0                 call    sub_7FF768136E44
```

These codes are passed to the same comparison function as the activation key. Performing analysis reveals that the other strings passed to this comparison are calculated from user input. Let's run the binary once again, grab the activation key from the debugger, then enter the codes:

```
Enter the activation key: 956182639
Congratulations! The key is correct.
Now to finish the crackme you need to complete the game and find the code.
Imagine that you are in a room with two code panels and a door. To open the door you need to find two codes.
Enter the codes in the "code1, code2" format
--------------------------------------------
Enter the codes: code@1F019,code@00111010_00110011
Congratulations!!! :3
```

Note that the program says to provide the codes with a space in the middle:

`code@1F019, code@00111010_00110011`

But this doesn't actually work. The correct string contains no space in between. 

***

### Locate the Activation Key Calculation

We now have the ability to solve a single iteration of the program, but we haven't solved this generally; the activation key changes every time the program runs. We need to find where the activation key is calculated.  

The actual calculation of this key value occurs in the instructions below. First a call to `sub_7FF768159A28` returns a value, then based on this value the program calculates the bytes of the activation code by choosing 2 bytes at a time from the string at:

`.rdata:00007FF7B375D05A a00010203040506` 

The final key is stored in the stack variable: `rsp+r8+2E8h+var_298+0Fh`. In my analysis of the program, this key has been between 8 and 10 bytes. 

```asm
.text:00007FF7681378D5                 lea     rcx, [rsp+2E8h+var_E8]
.text:00007FF7681378DD                 lea     rdi, [rsp+2E8h+name]
.text:00007FF7681378E2                 mov     r8d, 4
.text:00007FF7681378E8                 mov     rdx, rdi
.text:00007FF7681378EB                 call    sub_7FF768159A28
.text:00007FF7681378F0                 lea     rax, [rsp+2E8h+var_2B8]
.text:00007FF7681378F5                 and     qword ptr [rax], 0
.text:00007FF7681378F9                 mov     edi, [rdi]
.text:00007FF7681378FB                 mov     [rsp+2E8h+var_2B0], rax
.text:00007FF768137900                 mov     r8d, 20h ; ' '
.text:00007FF768137906                 mov     ecx, 64h ; 'd'
.text:00007FF76813790B                 lea     r15, a00010203040506 ; 
.text:00007FF768137912                 mov     eax, edi
.text:00007FF768137914                 cmp     eax, 64h ; 'd'
.text:00007FF768137917                 jb      short loc_7FF76813798B
.text:00007FF768137919                 xor     edx, edx
.text:00007FF76813791B                 div     ecx
.text:00007FF76813791D                 movzx   edx, word ptr [r15+rdx*2]
.text:00007FF768137922                 mov     word ptr [rsp+r8+2E8h+var_298+0Fh], dx
.text:00007FF768137928                 add     r8, 0FFFFFFFFFFFFFFFEh
.text:00007FF76813792C                 jmp     short loc_7FF768137914
...
.text:00007FF76813798B                 cmp     eax, 9
.text:00007FF76813798E                 ja      short loc_7FF7681379EC
.text:00007FF768137990                 add     al, 30h ; '0'
.text:00007FF768137992                 mov     byte ptr [rsp+r8+2E8h+name.sa_family], al
.text:00007FF768137997                 jmp     short loc_7FF7681379FC
...
.text:00007FF7681379EC                 mov     eax, eax
.text:00007FF7681379EE                 movzx   eax, word ptr [r15+rax*2]
.text:00007FF7681379F3                 mov     word ptr [rsp+r8+2E8h+var_298+0Fh], ax
.text:00007FF7681379F9                 dec     r8
```

It is my determination that `sub_7FF768159A28` is actually the Windows API function `CryptGenRandom`. This call produces a 4-byte random seed that the program uses to calculate the activation key. Because of this, it will be impossible for us to create a keygen to calculate this value at runtime. We will have to resort to other methods to obtain the key. 

***

Returning to the call of the comparison function discussed earlier:

```asm
.text:00007FF7681456CB                 test    rax, rax
.text:00007FF7681456CE                 cmovz   rdx, rax
.text:00007FF7681456D2                 mov     rcx, rax
.text:00007FF7681456D5                 lea     rax, unk_7FF7681912D3
.text:00007FF7681456DC                 cmovz   rcx, rax
.text:00007FF7681456E0                 mov     r8, [rsp+40h+arg_1B0]
.text:00007FF7681456E8                 mov     r9, [rsp+40h+arg_1B8]
.text:00007FF7681456F0                 call    sub_7FF768136E44
```

and scrolling up in the disassembly with `arg_1B0` selected, shows where the activation key value is used in other areas of the program. A hint is provided at `00007FF7681448DF` that this value might also be used as a session ID. 

```asm
.text:00007FF7681448C4                 mov     rax, [rsp+40h+arg_1B8]
.text:00007FF7681448CC                 mov     [rsp+40h+var_20], rax
.text:00007FF7681448D1                 mov     r8d, 0Ah
.text:00007FF7681448D7                 lea     rcx, [rsp+40h+arg_57F0]
.text:00007FF7681448DF                 lea     rdx, aSessionId ; "session-id"
.text:00007FF7681448E6                 mov     r9, [rsp+40h+arg_1B0]
.text:00007FF7681448EE                 call    sub_7FF76813129C
```

In our initial analysis of the network traffic, the session key `2293003546` did look quite familiar to the activation key format we're seeing now. 

Let's try it out. First start the program in its own windows terminal:

```
.\gameCrackme.exe
Enter the activation key: 
```

Before entering an activation key, query the netstat table for the web server port:

```
netstat -ano -p tcp
<SNIP>
 TCP    127.0.0.1:14495        0.0.0.0:0              LISTENING
```

Send a request to the web server to get the current session key:

```
curl.exe -v http://localhost:14495/check
<SNIP>
< HTTP/1.1 200 OK
< Connection: close
< Transfer-Encoding: chunked
< content-type: text/plain
< server: crackme :3
< session-id: 1047554161
<
false* Closing connection
```

Enter the key into the program:

```
.\gameCrackme.exe
Enter the activation key: 1047554161
Congratulations! The key is correct.
Now to finish the crackme you need to complete the game and find the code.
Imagine that you are in a room with two code panels and a door. To open the door you need to find two codes.
Enter the codes in the "code1, code2" format
--------------------------------------------
Enter the codes: code@1F019,code@00111010_00110011
Congratulations!!! :3
```
