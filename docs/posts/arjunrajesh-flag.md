---
draft: false 
date: 2024-02-11 
categories:
  - Reverse Engineering
tags:
  - x86_64
  - crackmes.one
slug: FLAG
---

# RE Challenge: ArjunRajesh's FLAG [on crackmes.one](https://crackmes.one/crackme/65a97cbaeef082e477ff5d84) 

***

### Binary 

```
Name: tryme
Application Type: ELF64 - Gentoo Linux(ABI: 3.2.0)[AMD64, 64-bit, DYN]
```

```cmd
$ ./tryme test
Wrong flag
```

<!-- more -->

***

### Analysis

At the beginning of the program, a pointer to the command line arguments (ARGV) is stored in the local variable `var_A0`:

```asm
.text:0000000000001176                 mov     [rbp+var_A0], rsi
```

The program then calculates the length of the value stored at `var_A0 + 8`. This represents ARGV[1], the flag supplied by the user. If the flag is not 21 characters exactly, the program exits.

```asm
.text:00000000000011AB                 mov     rax, [rbp+var_A0]
.text:00000000000011B2                 add     rax, 8
.text:00000000000011B6                 mov     rax, [rax]
.text:00000000000011B9                 mov     rdi, rax        ; s
.text:00000000000011BC                 call    _strlen
.text:00000000000011C1                 cmp     rax, 15h
.text:00000000000011C5                 jz      short loc_11DD
.text:00000000000011C7                 lea     rdi, aWrongFlag ; "Wrong flag"
```

Next the program takes a string from the `.rodata` section: `sup3r_s3cr3t_k3y_1337`, subtracts `0x22` from each character, and stores the resulting characters in the variable `var_20`. This data will be used later to test the flag supplied by the user.

```asm
.text:00000000000011DD                 lea     rax, aSup3rS3cr3tK3y
.text:00000000000011E4                 mov     [rbp+var_88], rax
.text:00000000000011EB                 mov     [rbp+var_90], 0
.text:00000000000011F5                 jmp     short loc_1225
.text:00000000000011F7                 mov     eax, [rbp+var_90]
.text:00000000000011FD                 movsxd  rdx, eax
.text:0000000000001200                 mov     rax, [rbp+var_88]
.text:0000000000001207                 add     rax, rdx
.text:000000000000120A                 movzx   eax, byte ptr [rax]
.text:000000000000120D                 sub     eax, 22h ; '"'
.text:0000000000001210                 mov     edx, eax
.text:0000000000001212                 mov     eax, [rbp+var_90]
.text:0000000000001218                 cdqe
.text:000000000000121A                 mov     [rbp+rax+var_20], dl
.text:000000000000121E                 add     [rbp+var_90], 1
.text:0000000000001225                 cmp     [rbp+var_90], 14h
.text:000000000000122C                 jle     short loc_11F7
```

Here we find the meat of the program. The program enters a loop and calculates:

```
RESULT = var_20[i] ^ FLAG[i]
```

If the result matches the character stored in `rbp+var_80[i]` the loop continues; otherwise the program exits printing `Wrong flag`.

```asm
.text:00000000000012CD                 mov     rax, [rbp+var_A0]
.text:00000000000012D4                 add     rax, 8
.text:00000000000012D8                 mov     rdx, [rax]
.text:00000000000012DB                 mov     eax, [rbp+var_8C]
.text:00000000000012E1                 cdqe
.text:00000000000012E3                 add     rax, rdx
.text:00000000000012E6                 movzx   edx, byte ptr [rax]
.text:00000000000012E9                 mov     eax, [rbp+var_8C]
.text:00000000000012EF                 cdqe
.text:00000000000012F1                 movzx   eax, [rbp+rax+var_20]
.text:00000000000012F6                 xor     eax, edx
.text:00000000000012F8                 movsx   edx, al
.text:00000000000012FB                 mov     eax, [rbp+var_8C]
.text:0000000000001301                 cdqe
.text:0000000000001303                 mov     eax, [rbp+rax*4+var_80]
.text:0000000000001307                 cmp     edx, eax
.text:0000000000001309                 jz      short loc_131E
.text:000000000000130B                 lea     rdi, aWrongFlag ; "Wrong flag"
.text:0000000000001312                 call    _puts
...
.text:000000000000131E                 add     [rbp+var_8C], 1
.text:0000000000001325                 cmp     [rbp+var_8C], 14h
.text:000000000000132C                 jle     short loc_12CD
```

If every character is a match, the program prints the success message. To find the flag we can take advantage of the fact that: 

```
if
A XOR B = C
then
B = C XOR A
```

```
FLAG = flag{_y0u_f0und_key_}
```

Reference the keygen below or in keygen.py.

***

### Keygen

```python title="keygen.py"
def transform(data):
        OUT = []
        for ch in data:
                OUT.append(ord(ch) - 34)
        return OUT

if __name__ == "__main__":

        KEY = "sup3r_s3cr3t_k3y_1337"

        XOR_RES = [0x37, 0x3f, 0x2f, 0x76, 0x2b, 0x62, 0x28, 0x21, 0x34, 0xf,
        0x77, 0x62, 0x48, 0x27, 0x75, 0x8, 0x56, 0x6a, 0x68, 0x4e, 0x68]

        x = transform(KEY)

        # x[i] ^ FLAG[i] = XOR_RES[i]
        # ->
        # FLAG[i] = XOR_RES[i] ^ x[i]

        FLAG = []

        for i in range(21):
                FLAG.append(chr(XOR_RES[i] ^ x[i]))

        print("FLAG: {}".format("".join(FLAG)))
```
