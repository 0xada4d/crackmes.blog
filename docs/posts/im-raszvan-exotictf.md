---
draft: false 
date: 2024-03-08
categories:
  - Reverse Engineering
tags:
  - x86_64
  - crackmes.one
  - swift
slug: exotictf
---

# RE Challenge: im-razvan's ExotiCTF [on crackmes.one](https://crackmes.one/crackme/65c4021aeef082e477ff688a)

***

### Binary 

```
Name: exotictf1.exe 
Application Type: PE64 - Windows(Vista)[AMD64, 64-bit, Console]
```

```cmd
$ .\exotictf1.exe
Enter the PIN : 1234
Wrong PIN! Try again.
```

<!-- more -->

***

### Analysis

At the beginning of `main`, the program passes a seed to the PIN generation function `$s8exotictf8xyxyxyxyyS2iF`:

```asm
.text:00007FF7A4D112AE                 mov     ecx, 0Bh        ; input
.text:00007FF7A4D112B3                 call    $s8exotictf8xyxyxyxyyS2iF
```

This function takes the seed and converts it to ASCII representation:

`0xB = 0x3131 = '11'`

```asm
.text:00007FF7A4D118B0                 call    $sS2is23CustomStringConvertiblesWl
.text:00007FF7A4D118B5                 mov     rcx, cs:$sSiN
.text:00007FF7A4D118BC                 lea     r13, [rsp+68h+var_48]
.text:00007FF7A4D118C1                 mov     rdx, rax
.text:00007FF7A4D118C4                 call    cs:$ss23CustomStringConvertibleP11descriptionSSvgTj
.text:00007FF7A4D118CA                 mov     [rsp+68h+var_48], rax
.text:00007FF7A4D118CF                 mov     [rsp+68h+var_40], rdx
```

Next the program processes the ASCII string byte by byte, beginning with the lowest order byte. For a detailed analysis of the algorithm, check the [keygen](#keygen). 

At a high level, it takes the current byte and subtracts `0x30` to get the `INT` value of the byte. It then performs operations based on the number of remaining bytes, and aggregates the resulting value into a sum. After processing all the bytes of the ASCII representation, the resulting sum is used in further mathematical operations to create a hash value that will be used as a PIN.

Solving this challenge was straightforward due to the fact that the program uses a single seed value: `0xB`. Placing a breakpoint after the call to the PIN generation function (`.text:00007FF7A4D112B8`) and inspecting the return value reveals the correct pin:

`PIN = 0x17D140 = 1560896`

The [keygen](#keygen) will provide this value for you as well and show you how it is calculated. Let's test:

```
$ .\exotictf1.exe
Enter the PIN : 1560896
The pin is correct! The flag is CTF{by-im-razvan-1560896}
```

***

### Keygen

```c title="keygen.c"
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <intrin.h>

#pragma intrinsic(_mul128)

int chr_to_int(unsigned char x)
{
    return x - 0x30;
}

int main()
{
  // SEED value
    int INPUT = 0xB;

  // .text:00007FF7A4D118B0 
    char INPUT_STR[16] = { 0 };
    sprintf(INPUT_STR, "%d", INPUT);
    int INPUT_STR_SZ = strlen(INPUT_STR);

    int SUM = 0;

  // .text:00007FF7A4D11A7B
    if (INPUT_STR_SZ == 1)
    {
        SUM += chr_to_int(INPUT_STR[0]);
    }
    else if (INPUT_STR_SZ == 2)
    {
        int RES = (chr_to_int(INPUT_STR[1])) + (chr_to_int(INPUT_STR[1]) * 4);
        SUM += chr_to_int(INPUT_STR[0]) + (RES * 2);
    }
    else
    {
        int RES = (chr_to_int(INPUT_STR[INPUT_STR_SZ - 1])) + (chr_to_int(INPUT_STR[INPUT_STR_SZ - 1]) * 4);
        SUM += chr_to_int(INPUT_STR[INPUT_STR_SZ - 2]) + (RES * 2);
        for (int i = INPUT_STR_SZ - 3; i >= 0; i--)
        {
            SUM *= 10;
            SUM += chr_to_int(INPUT_STR[i]);
        }
    }

  // .text:00007FF7A4D11B2D
    SUM *= 2;
    SUM += 2;

    int TMP = (SUM * 4) + 2;
    TMP *= 3;

    __int64 val = 0xA3D70A3D70A3D70BI64;
    __int64 val2 = (__int64)TMP;
    __int64 h, l;

    l = _mul128(val, val2, &h);

    __int64 RES = h + (__int64)TMP;
    unsigned __int64 a = (unsigned __int64)(RES >> 0x3F);
    
    __int64 b = RES >> 6;

    __int64 c = a + b;

    __int64 d = c * 0x64;

    __int64 e = (__int64)TMP - d;

    __int64 f = e ^ 0x2A;

    __int64 g = f * f;

    g *= f;

    printf("PIN: %lld", g);


    return 0;
}

```

