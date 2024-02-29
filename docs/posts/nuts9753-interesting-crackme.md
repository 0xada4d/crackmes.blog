---
draft: false 
date: 2024-02-24 
categories:
  - Reverse Engineering
tags:
  - x86_64
  - crackmes.one
slug: interesting-crackme
---

# RE Challenge: nuts9753's interesting crackme [on crackmes.one](https://crackmes.one/crackme/659fff95eef082e477ff59de) 

***

### Binary 

```
Name: crackme.exe
Application Type: PE64 - Windows(Vista)[AMD64, 64-bit, Console]
```

```cmd
$ .\crackme.exe
Enter the code: test
The code is incorrect!
```

<!-- more -->

***

### Analysis

Near the beginning of the `start` function, we find the request for the code:

```
.text:0000000140001209                 lea     rdx, aEnterTheCode 
.text:0000000140001210                 mov     r8d, 10h
.text:0000000140001216                 call    sub_140001AB0
```

The program reads the input data from STDIN one byte at a time using the Windows `ReadFile` function:

```
.text:000000014000127E                 and     [rsp+40h+var_20], 0
.text:0000000140001284                 mov     rcx, rsi        ; hFile
.text:0000000140001287                 mov     rdx, rbx        ; lpBuffer
.text:000000014000128A                 mov     r8d, 1          ; nNumberOfBytesToRead
.text:0000000140001290                 mov     r9, r14         ; lpNumberOfBytesRead
.text:0000000140001293                 call    ReadFile
```

The user input is stored as an array of characters in the `.debug` segment of the binary.

To calculate the actual code, the program first calls `GetCurrentDirectoryW`:

```
.text:0000000140001533                 lea     rdx, [rsp+40h+NumberOfBytesRead] 
.text:000000014000153B                 mov     ecx, 7FFFh      ; nBufferLength
.text:0000000140001540                 call    GetCurrentDirectoryW
```

This function returns the fully qualified path (Unicode) to the directory from which `crackme.exe` was executed. After converting this value from Unicode to ASCII, the program reverses the order of the bytes of the string:

```
.text:0000000140001784                 cmp     rax, rdx
.text:0000000140001787                 jz      short loc_1400017C4
.text:0000000140001789                 mov     r8b, [r11+rdx]
.text:000000014000178D                 mov     r9b, [rcx]
.text:0000000140001790                 mov     [r11+rdx], r9b
.text:0000000140001794                 mov     [rcx], r8b
.text:0000000140001797                 inc     rdx
.text:000000014000179A                 dec     rcx
.text:000000014000179D                 jmp     short loc_140001784
```

The program takes the reversed directory string and enters a loop to calculate the secret code. For each byte of the reversed string, the loop calculates an offset into a dictionary string, and returns two bytes from that dictionary.

```
.text:00000001400018DF                 cmp     bpl, 64h ; 'd'
.text:00000001400018E3                 jb      short loc_140001902
.text:00000001400018E5                 movzx   eax, bpl
.text:00000001400018E9                 div     r12b
.text:00000001400018EC                 movzx   ecx, ah
.text:00000001400018EF                 movzx   ecx, word ptr [r15+rcx*2]
.text:00000001400018F4                 mov     [rsp+r8+2Fh], cx
```

The dictionary is defined in the `.rdata` section:

```
.rdata:0000000140003150 a00010203040506 db '00010203040506070809101112131415161718192021222324252627282930313'
.rdata:0000000140003150                                         
.rdata:0000000140003191                 db '23334353637383940414243444546474849505152535455565758596061626364'
.rdata:00000001400031D2                 db '65666768697071727374757677787980818283848586878889909192939495969'
.rdata:0000000140003213                 db '79899',0
```

When the current byte value is larger that `0x64`, the program appends a third byte to the bytes returned from the dictionary. 

```
.text:0000000140001902                 cmp     bpl, 9
.text:0000000140001906                 ja      short loc_140001913
.text:0000000140001908                 add     bpl, 30h ; '0'
.text:000000014000190C                 mov     byte ptr [rsp+r8+40h+var_10], bpl
.text:0000000140001911                 jmp     short loc_140001925

.text:0000000140001913                 movzx   eax, bpl
.text:0000000140001917                 movzx   eax, word ptr [r15+rax*2]
.text:000000014000191C                 mov     [rsp+r8+2Fh], ax
.text:0000000140001922                 dec     r8
```

When the loop counter is odd (`i % 2 != 0`), the program adds a space (`0x20`) to the byte string. 

The important validation occurs here:

```
.text:000000014000199E                 mov     rcx, [rsp+40h+arg_88]
.text:00000001400019A6                 mov     rdx, [rsp+40h+arg_90]
.text:00000001400019AE                 lea     r8, unk_1400030C0
.text:00000001400019B5                 call    sub_14000112B
.text:00000001400019BA                 mov     esi, 2
.text:00000001400019BF                 lea     rcx, unk_1400030DA
.text:00000001400019C6                 cmp     [rsp+40h+arg_28], rdx
.text:00000001400019CB                 jnz     short loc_1400019F6
.text:00000001400019CD                 cmp     [rsp+40h+arg_20], rax
.text:00000001400019D2                 jnz     short loc_1400019D8
```

The program first checks that the length of the user input string matches the length of the code string (`00000001400019C6`). If the lengths match, the values are compared (`00000001400019CD`).

Review keygen.py to get a better picture of the program behavior. 

Let's test it out:
```
$ cd C:\Windows\Temp
$ .\crackme.exe
Enter the code: 112109 10184 92115 119111 100110 10587 9258 67
The code is correct!
```


***

### Keygen

```python title="keygen.py"
DICT_STR = "00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899"
DICT = list(DICT_STR)

# Change this directory to match where you executed crackme.exe
d = "C:\\Windows\\Temp"
r = d[::-1]

SECRET_CODE = ""

for i in range(len(r)):
  CODE_WORD = ""
  if ord(r[i]) >= 0x64:
    CODE_WORD += chr(0x30 + (ord(r[i]) // 0x64))
    CODE_WORD += DICT[(ord(r[i]) % 0x64) * 2]
    CODE_WORD += DICT[((ord(r[i]) % 0x64) * 2) + 1] 
  else:
    CODE_WORD += DICT[(ord(r[i]) * 2)]
    CODE_WORD += DICT[(ord(r[i]) * 2) + 1]

  if i % 2 != 0:
    CODE_WORD += " "

  SECRET_CODE += CODE_WORD

print(SECRET_CODE)

```

