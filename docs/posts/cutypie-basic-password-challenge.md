---
draft: false 
date: 2024-02-11 
categories:
  - Reverse Engineering
tags:
  - x86_64
  - crackmes.one
slug: basic-password-challenge
---

# RE Challenge: cutypie's Basic Password Challenge [on crackmes.one](https://crackmes.one/crackme/65bfedcaeef082e477ff66aa) 



### Binary
	Name: basic.exe
	Application Type: Windows(Vista)[AMD64, 64-bit, Console]

```cmd
$ .\basic.exe
Username: test
Enter your password: test
Invalid input. Please enter a valid unsigned integer: 1111
Bad
```

<!-- more -->

### Analysis

The program begins by requesting the username from the user with the first call to `fgets`:

```
.text:00000001400010EF                 mov     r8, rax         ; Stream
.text:00000001400010F2                 lea     edx, [rsi+64h]  ; MaxCount
.text:00000001400010F5                 lea     rcx, [rsp+0B8h+Buffer] ; Buffer
.text:00000001400010FA                 call    cs:fgets
```

The username is stored on the stack at `rsp+0B8h+Buffer`. The program calculates the length of the supplied username and stores the value in `rdi`:

```
.text:0000000140001111                 inc     rdi
.text:0000000140001114                 cmp     [rax+rdi], sil
.text:0000000140001118                 jnz     short loc_140001111
```


Next, the program uses the C++ `std::cin` to get the password:

```
.text:0000000140001135                 mov     rcx, cs:?cin@std... 
.text:000000014000113C                 lea     rdx, [rsp+0B8h+var_98]
.text:0000000140001141                 call    cs:??5?$basic_istream@...
```

The password is stored at `rsp+0B8h+var_98`.

The next portion of the disassembly was slightly confusing at first, but this is where the program checks that the user supplied an integer as a password:

```
.text:0000000140001151                 mov     rcx, [rax]
.text:0000000140001154                 movsxd  rdx, dword ptr [rcx+4]
.text:0000000140001158                 test    byte ptr [rdx+rax+10h], 6
.text:000000014000115D                 jz      short loc_1400011C6
```

Assuming the user supplies an integer password, the program checks that the username actually contains data. Then based on the length of the username, branches to one of two locations to begin the calculation of the correct password.

```
.text:00007FF7F93A11DC                 lea     rax, [rsp+0B8h+Buffer]
.text:00007FF7F93A11E1                 cmp     rax, rbp
.text:00007FF7F93A11E4                 cmova   rdi, rsi
.text:00007FF7F93A11E8                 test    rdi, rdi
.text:00007FF7F93A11EB                 jz      short loc_7FF7F93A125A
.text:00007FF7F93A11ED                 cmp     rdi, 8
.text:00007FF7F93A11F1                 jb      short loc_7FF7F93A125A
```

If the username string is less than 8 bytes (including the `\n`) the program branches here and calculates the sum of the ASCII values of the username characters:

```
.text:00007FF7F93A1260                 movsx   eax, byte ptr [rbx]
.text:00007FF7F93A1263                 inc     rbx
.text:00007FF7F93A1266                 add     esi, eax
.text:00007FF7F93A1268                 cmp     rbx, rbp
.text:00007FF7F93A126B                 jnz     short loc_7FF7F93A1260
```

If the username string is greater than 8 bytes the floating point registers are used to perform the calculation. 

Finally the sum of the ASCII characters in the username is checked against the integer provided as the password. Assuming the two values are equal, the program prints the `Correct Password` message.

```
.text:00007FF7F93A126D                 cmp     [rsp+0B8h+var_98], esi
.text:00007FF7F93A1271                 lea     rax, aBad       ; "Bad\n"
.text:00007FF7F93A1278                 lea     rcx, aCorrectPasswor ; 
.text:00007FF7F93A127F                 cmovnz  rcx, rax        ; Format
.text:00007FF7F93A1283                 call    sub_7FF7F93A1010
```

### Keygen

```python
def generate_code(username):
	total = 0
	for ch in username:
		total += ord(ch)
	total += ord('\n')
	print("Password -> {}".format(total))


if __name__ == "__main__":
        user = input("Enter username: ")
        generate_code(user)

```
