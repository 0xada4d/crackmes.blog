---
draft: false 
date: 2024-02-10 
categories:
  - Reverse Engineering
tags:
  - x86_64
  - crackmes.one
slug: easy-password-reverse-2
---

# RE Challenge: Clyax's Easy Password Reverse 2 [on crackmes.one](https://crackmes.one/crackme/65c0e7bfeef082e477ff672a) 


### Binary

```
Name: reverse.exe
Application Type: Windows(Server 2003)[AMD64, 64-bit, Console]
```

```cmd
$ .\reverse.exe
Username: test
Password: test
Bad
```

<!-- more -->


### Analysis

The binary starts with two calls to `fgets` to get the username and password from the user:

```asm
.text:0000000140007CBC                 mov     edx, 3E8h       ; MaxCount
.text:0000000140007CC1                 mov     rcx, r13        ; Buffer
.text:0000000140007CC4                 mov     r8, rax         ; Stream
.text:0000000140007CC7                 call    fgets
.text:0000000140007CCC                 mov     rcx, rdi        ; __format
.text:0000000140007CCF                 call    _text_47
.text:0000000140007CD4                 xor     ecx, ecx        ; index
.text:0000000140007CD6                 call    rsi ; __acrt_iob_func
.text:0000000140007CD8                 mov     edx, 3E8h       ; MaxCount
.text:0000000140007CDD                 mov     rcx, r12        ; Buffer
.text:0000000140007CE0                 mov     r8, rax         ; Stream
.text:0000000140007CE3                 call    fgets
```

It then verifies that the user actually entered data. If an empty string was supplied by the user, the program repeats the calls to `fgets`:

```asm
.text:0000000140007CEE                 call    strcspn
.text:0000000140007CF3                 mov     rdx, rbx        ; Control
.text:0000000140007CF6                 mov     rcx, r12        ; Str
.text:0000000140007CF9                 mov     [rsp+rax+858h+user], 0
.text:0000000140007CFE                 call    strcspn
.text:0000000140007D03                 cmp     [rsp+858h+user], 0
.text:0000000140007D08                 mov     [rsp+rax+858h+pw], 0
.text:0000000140007D10                 jz      short loc_140007CB0
.text:0000000140007D12                 cmp     [rsp+858h+pw], 0
.text:0000000140007D1A                 jz      short loc_140007CB0
```

Assuming that the user actually entered a string, the program passes the username string and a buffer to the function `_Z12Q2FsY3VsYXRlPcS_`. This function creates a pass-code based on the username string, and stores the pass-code in the buffer. To simplify analysis, I will rename this function to `generate_code`.

`generate_code` begins by entering a loop, calculating the length of the username string provided by the user. 

```asm
.text:0000000140001571                 mov     rcx, rsi        ; Str
.text:0000000140001574                 call    strlen
```

It then picks two characters from the username string using an iterator (rbx) modulo string length:

```
username[iterator % len(username)]
username[iterator+3 % len(username)]
```

```asm
.text:0000000140001579                 xor     edx, edx
.text:000000014000157B                 mov     rcx, rax
.text:000000014000157E                 mov     rax, rbx
.text:0000000140001581                 div     rcx
.text:0000000140001584                 lea     rax, [rbx+3]
.text:0000000140001588                 movzx   r12d, byte ptr [rsi+rdx]
.text:000000014000158D                 xor     edx, edx
.text:000000014000158F                 div     rcx
.text:0000000140001592                 mov     rcx, rdi        ; Str
.text:0000000140001595                 movzx   r13d, byte ptr [rsi+rdx]
```

It then checks the iterator. If the iterator is even, it performs an `AND` operation on these two characters. If the iterator is odd, it performs `XOR`.

```asm
.text:00000001400015A2                 test    bl, 1
.text:00000001400015A5                 jz      short loc_140001550
.text:00000001400015A7                 xor     r12d, r13d
...
.text:0000000140001550                 and     r12d, r13d
```

In the final step of the loop, a character from the substitution dictionary is added to the pass-code string. You can find the dictionary in the variable `dir`, stored in the .data section of the binary:

```asm
.data:0000000140008020 dir             db 'abcdefghijklmnopqr..."
```

The function picks the character from the dictionary using the result of the `XOR` or `AND` operation, modulo the length of the dictionary:

```
char_to_add = dir[result % len(dir)]
pass_code[iterator] = char_to_add
```

```asm
.text:0000000140001553                 movsx   rax, r12b
.text:0000000140001557                 xor     edx, edx
.text:0000000140001559                 div     rcx
.text:000000014000155C                 movsxd  rdx, edx
.text:000000014000155F                 movzx   eax, byte ptr [rdi+rdx]
.text:0000000140001563                 mov     [rbp+rbx+0], al
```

The loop is now complete, the character added to the pass-code. The iterator is incremented by 1 and the loop restarts.

```asm
.text:0000000140001567                 add     rbx, 1
.text:000000014000156B                 cmp     rbx, 12h
.text:000000014000156F                 jz      short loc_1400015B0
```

When calling this function `generate_code`, the first three characters of the pass-code have already been determined:

```
pass_code = ["C", "l", "@"]
```

Therefore the loop inside of `generate_code` begins at iterator=3 and loops 15 times, until iterator=18. The final result of this function is a pass-code that is 18 characters in length.

The important comparison occurs back in the main function: the password that the user entered is checked against the generated pass-code:

```asm
.text:0000000140007D27                 call    generate_code
.text:0000000140007D2C                 mov     rdx, r12        ; Str2
.text:0000000140007D2F                 mov     rcx, r14        ; Str1
.text:0000000140007D32                 call    strcmp
.text:0000000140007D37                 test    eax, eax
.text:0000000140007D39                 jz      short loc_140007D5B
.text:0000000140007D3B                 lea     rcx, aBad       ; "Bad\n"
```

If the entered password matches the pass-code, the "Good" message is printed to the screen. 


### Keygen

```python title="keygen.py"

charlist = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

code = ["C", "l", "@"]

def generate_code(username):
        len_username = len(username)
        len_charlist = len(charlist)


        for i in range(3, 18):
                x = username[(i) % len_username]
                y = username[(i+3) % len_username]

                if i % 2 == 0:
                        result = ord(x) & ord(y)
                else:
                        result = ord(x) ^ ord(y)

                code.append(charlist[result % len_charlist])

if __name__ == "__main__":
        user = input("Enter username: ")

        generate_code(user)
        print("".join(code))


```

