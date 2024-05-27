---
draft: false 
date: 2024-05-27 
categories:
  - Reverse Engineering
tags:
  - x86_64
  - crackmes.one
slug: pupsik-difficult
---

# RE Challenge: Pupsik's difficult crackme [on crackmes.one](https://crackmes.one/crackme/65ccb049eef082e477ff6d2c)

***

### Binary 

```
Name: Project10.exe 
Application Type: Windows(Vista)[AMD64, 64-bit, Console]
```

```cmd
$ .\Project10.exe
Enter the username: test
Enter the password: test
Incorrect password. Try again.
```

<!-- more -->

***

### Analysis

Binary Ninja identifies `main` at offset `1a090`. 

The `main` function first asks for a username. This value is processed by the function `sub_140019410`. For ease of explanation, I will call this function `CHECK_USERNAME`.

`CHECK_USERNAME` performs operations on the username based on its length, with the length calculation happening here:

```asm
1400194bf  mov     rcx, qword [rbp+0x230 {arg_8}]
1400194c6  call    j_sub_140019bf0
```

Analyzing `sub_140019bf0` you find that that instead of using a method to count the bytes of the string, such as `strlen`, the length is retrieved from a specific offset  inside the string object: `&string+0x18`

```asm
140019c0f  mov     rax, qword [rbp+0xe0 {arg_8}]
140019c16  mov     rax, qword [rax+0x18]
```

If you were to decompile this code manually, the above block probably looked something like this:

```cpp
x = string.length()
```

Based on the length, `CHECK_USERNAME` appends characters to the `"PASSWORD=123"` string within the binary. From my analysis, this seems to be irrelevant to the operation of the program. 

The important check within `CHECK_USERNAME` occurs here:

```asm
1400195e9  lea     rdx, [rel data_140036bd8]  {"admin"}
1400195f0  mov     rcx, qword [rbp+0x230 {arg_8}]
1400195f7  call    j_sub_140014190
1400195fc  movzx   eax, al
1400195ff  test    eax, eax
140019601  je      0x14001961e
```

If you enter `"admin"` as the username, the program will exit, printing the `Invalid username.` message. So really, any username works as long as it is not `admin`.

---

Returning to `main`, the next request is for a password:

```asm
14001a118  lea     rdx, [rel data_140036c00]  {"Enter the password: "}
14001a11f  mov     rcx, qword [rel std::cout]
14001a126  call    j_sub_140013c90
14001a12b  lea     rdx, [rbp+0x48 {var_130}]
14001a12f  mov     rcx, qword [rel std::cin]
14001a136  call    j_sub_140013850
14001a13b  lea     rcx, [rbp+0x48 {var_130}]
14001a13f  call    j_sub_140018fd0
```

The password value is processed by `sub_140018fd0`. I will refer to this function as `CHECK_PASSWORD`.

`CHECK_PASSWORD` creates a copy of the password here:

```asm
140019019  mov     rdx, qword [rbp+0x3f0 {arg_8}]
140019020  lea     rcx, [rbp+0x8 {var_3e0}]
140019024  call    j_sub_140015ea0
```

The copy is stored in `var_3e0`. A few function calls later, this copy is reversed (i.e. `"abcd" -> "dcba"`) with the call to `sub_1400157d0`:

```asm
14001906d  mov     qword [rbp+0x3c0 {var_28}], rax
140019074  mov     rdx, qword [rbp+0x3b8 {var_30}]
14001907b  mov     rcx, qword [rbp+0x3c0 {var_28}]
140019082  call    j_sub_1400157d0
```

Then the original password and the reversed copy are passed as parameters to `sub_1400141f0`:

```asm
140019087  lea     rdx, [rbp+0x8 {var_3e0}]
14001908b  mov     rcx, qword [rbp+0x3f0 {arg_8}]
140019092  call    j_sub_1400141f0
```

If you drill down into the many function calls within `sub_1400141f0`, you will eventually find a call to `memcmp`:

```asm
140014214  mov     rdx, qword [rbp+0xf8 {arg_10}]
14001421b  mov     rcx, qword [rbp+0xf0 {arg_8}]
140014222  call    j_sub_140014130
...
140014162  call    j_sub_140017e90
...
140017ef9  call    j_sub_1400152b0
...
140015303  call    j_sub_140019710
...
14001974e  call    sub_140011316
...
sub_140011316:
140011316  jmp     memcmp
```

If the two strings are not the same, `CHECK_PASSWORD` exits, returning 0, and the program prints the `Incorrect password. Try again.` message. 

If the two strings are the same, `CHECK_PASSWORD` continues execution. Conclusion: the password must be a palindrome. 

Next, similar to the behavior of `CHECK_USERNAME`, `CHECK_PASSWORD` performs operations on a string in the binary (`"junk"`) based on the length of the password string. However these operations also seem to be irrelevant to the operation of the program.

The length of the password string is checked here:

```asm
140019235  mov     rcx, qword [rbp+0x3f0 {arg_8}]
14001923c  call    j_sub_140019950
```

The password length must be greater than zero.

Next, there are two checks that the password string is not `pupsik:`

```asm
140019270  lea     rdx, [rel data_140036bbc]  {"pupsik"}
140019277  mov     rcx, qword [rbp+0x3f0 {arg_8}]
14001927e  call    j_sub_140014190
140019283  movzx   eax, al
140019286  test    eax, eax
140019288  je      0x1400192af
```

`sub_140014190` eventually calls `memcmp`. If the password is `"pupsik"`, `CHECK_PASSWORD` returns 0 and the invalid password message prints to the screen. The purpose of these two checks is a bit unclear to me; if a user typed in a password of `"pupsik"`, `CHECK_PASSWORD` would have exited before this check ever happens because "pupsik" is not a palindrome. 

At this point the `CHECK_PASSWORD` has mostly completed. If the user's password is a palindrome (and not equal to "pupsik"??) the function returns a non-zero value, and the success message is printed to the screen:

```
Enter the username: anything
Enter the password: amanaplanacanalpanama
Congratulations! You have entered the correct username and password.
```

***

### Keygen

```python title="keygen.py"

Not necessary - just enter a palindrome as the password!!

```
