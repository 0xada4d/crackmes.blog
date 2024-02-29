---
draft: false 
date: 2024-02-28 
categories:
  - Reverse Engineering
tags:
  - x86_64
  - crackmes.one
  - frida
slug: obfuscation-fiesta
---

# RE Challenge: mstik13's ObfuscationFiesta [on crackmes.one](https://crackmes.one/crackme/65acadf3eef082e477ff5ede) 

***

### Binary 

	Name: ObfuscationFiesta.exe
	Application Type: PE64 - Windows(Vista)[AMD64, 64-bit, Console]

```cmd
$ .\ObfuscationFiesta.exe
Enter a key: test
Loading: ==========
Loading: ==========
Loading: ==========
Enter the secret code (Hint: Combine odd and even numbers): 234567
Incorrect secret code. Verification failed.
```

<!-- more -->

***

### Analysis

With no knowledge of instrumentation tools, this challenge is pretty difficult due to the fact that the program does its best to prevent you from performing live debugging. I was pulling my hair out until I learned Frida, which is how I solved this challenge. Details will follow below, and see the keygen for the script.

The program uses many common Windows anti-debugging techniques and APIs including:

```
IsDebuggerPresent
CheckRemoteDebuggerPresent
GetTickCount
QueryPerformanceCounter
NtQueryInformationProcess
Searching for windows with blacklisted names (OLLYDBG, etc)
...
```

On detection of a debugger, the program throws an exception and stops execution.

Scrolling past the anti-debugging portion of the program, we find the first clue as to what the program is doing:

```asm
.text:00000001400030BB                 xor     ecx, ecx        ; Time
.text:00000001400030BD                 call    cs:_time64
.text:00000001400030C3                 mov     [rsp+948h+var_6D0], rax
.text:00000001400030CB                 mov     r9, [rsp+948h+var_6D0]
.text:00000001400030D3                 lea     r8, aLd         ; "%ld"
.text:00000001400030DA                 mov     edx, 14h
.text:00000001400030DF                 lea     rcx, [rsp+948h+var_A8]
.text:00000001400030E7                 call    sub_140001180
```

Here the program calls the `__time64` function to get the system epoch time. It proceeds to store this value as a string on the stack using `vsprintf`. 

Shortly after this, we see the `fgets` call to get the "key" from the user:

```asm
.text:000000014000312C                 xor     ecx, ecx        ; Ix
.text:000000014000312E                 call    cs:__acrt_iob_func
.text:0000000140003134                 mov     r8, rax         ; Stream
.text:0000000140003137                 mov     edx, 64h ; 'd'  ; MaxCount
.text:000000014000313C                 lea     rcx, [rsp+948h+Buffer] ; Buffer
.text:0000000140003144                 call    cs:fgets
```

The program then takes the user input and encodes each byte:

```asm
.text:00000001400031CF                 movsx   eax, [rsp+rax+948h+Buffer]
.text:00000001400031D7                 xor     eax, 0FFh
.text:00000001400031DC                 add     eax, 0Fh
.text:00000001400031DF                 mov     rcx, [rsp+948h+var_848]
.text:00000001400031E7                 mov     [rsp+rcx+948h+Buffer], al
```

i.e. `INPUT[i] = (INPUT[i] ^ 0xFF) + OxF`

The program takes this XOR encoded key and appends it to the time string with another call to `vsprintf`:

```asm
.text:00000001400031F0                 lea     rax, [rsp+948h+Buffer]
.text:00000001400031F8                 mov     [rsp+948h+var_928], rax
.text:00000001400031FD                 lea     r9, [rsp+948h+var_A8]
.text:0000000140003205                 lea     r8, aSS         ; "%s%s"
.text:000000014000320C                 mov     rdx, [rsp+948h+Size]
.text:0000000140003214                 mov     rcx, [rsp+948h+Block]
.text:000000014000321C                 call    sub_140001180
```

Starting here the program loops through each byte of the TIME+INPUTXOR string, performing a bunch of mathematical operations and calculates a the "secret code":

```asm
.text:00000001400033C4                 mov     rax, [rsp+948h+var_8D0]
.text:00000001400033C9                 mov     rcx, [rsp+948h+Block]
.text:00000001400033D1                 add     rcx, rax
.text:00000001400033D4                 mov     rax, rcx
.text:00000001400033D7                 movsx   eax, byte ptr [rax]
.text:00000001400033DA                 mov     ecx, [rsp+948h+var_918]
....
many, many lines of bit-shifting, multiplication, division, etc
...
```

Appended to this walkthrough is my failed attempt at writing this algorithm in C: 
[Keygen - Non-Working](#keygen-non-working)

I spent a lot of time debugging this code but I can't get it to work. If someone reads this and gets the algorithm to work, I'd appreciate you commenting and telling me what I did wrong (probably a lot). 

The final result of the calculation is stored here:

```asm
.text:0000000140003AC2                 mov     eax, [rsp+948h+var_84C]
.text:0000000140003AC9                 mov     [rsp+948h+var_7F8], eax
```

And the important comparison to the user-input "secret code" occurs here:

```asm
.text:0000000140003C73                 mov     eax, [rsp+948h+var_7F8]
.text:0000000140003C7A                 cmp     [rsp+948h+var_5B0], eax
.text:0000000140003C81                 jnz     short loc_140003CC5
```

Because I couldn't get my C code to work, I decided to spend some time learning Frida. The working keygen below uses Frida to instrument the binary, and pull the relevant value from memory:

```
In terminal A:
> .\ObfuscationFiesta.exe

In terminal B:
> tasklist | findstr Obf
ObfuscationFiesta.exe          364 Console                    1      3,944 K

> frida -l keygen.js 364

Return to terminal A:
> Enter a key: test

View the output in B:
[Local::PID::364 ]-> Secret Code: 4294965075

Return to terminal A:
Enter a key: test
Loading: ==========
Loading: ==========
Loading: ==========
Enter the secret code (Hint: Combine odd and even numbers): 4294965075
Secret code accepted. Verification successful.

```


***

### Keygen - Working

```javascript title="keygen.js"

// Process:
// Launch ObfuscationFiesta.exe in a terminal
// Open another terminal and run test.js with Frida:
// > frida -l test.js <PID_OF_OBFUSCATIONFIESTA_EXE>

var moddata = Process.getModuleByName("ObfuscationFiesta.exe");

// Find the offset where the value is stored using IDA
// .text:0000000140003AC9                 mov     [rsp+948h+var_7F8], eax
var codePtr = moddata.base.add("0x3AC9");

Interceptor.attach(codePtr, function() {
	console.log('Secret Code: ' + this.context.rax.toUInt32());
});

```


***
### Keygen - Non-Working

```c
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#define MAX 1024

int main() {

	char buf[MAX];
	char key[MAX];
	char buf_mod[MAX];

	char* time_str = "1709084040";

	memset(key, 0, MAX);
	memset(buf, 0, MAX);
	memset(buf_mod, 0, MAX);

	vfprintf(stdout, "Enter a key: ", 0);
	fgets(buf, MAX, stdin);

	for (int i = 0; i < strlen(buf); i++)
	{
		buf_mod[i] = (buf[i] ^ 0xFF) + 0xF;
	}

	strcat(key, time_str);
	strcat(key, buf_mod);

	int VAL = 0;
	int MULT = 0x1F;

	int CUR_TIME_LEN = strlen(key);

	for (int i = 0; i < CUR_TIME_LEN; i++)
	{
		int CBX = VAL ^ key[i];
		int r1 = CBX << (i % 8);
		int r2 = CBX >> (8 - (i % 8));
		int r3 = r1 | r2;

		VAL = r3 ^ (i * 0x89);
		
		int r5 = VAL >> 7;
		int r6 = r5 + (VAL * 8);
		int x = i * 0x49;
		int r7 = r6 + x;

		VAL = VAL + r7;
		
		int y = VAL << 5;
		int z = VAL >> 0xB;
		int r8 = y + z;
		int a = i * MULT;
		r8 = r8 - a;

		VAL = VAL ^ r8;
		VAL = ~(VAL ^ CBX) | (VAL & CBX);

		int b = VAL * i;
		int c = i % 0x11;
		int d = i + 1;
		
		VAL = b ^ (c + (VAL / d));

		int r9 = (VAL << 2) ^ (VAL >> 0xA);
		int r10 = 1;

		VAL = r9 | (VAL & (r10 << (i % 4)));
				
	}

	int VAL0 = VAL;
	if ((((VAL & 1) ^ ((CUR_TIME_LEN - 1) % 4)) - ((CUR_TIME_LEN - 1) % 4)) == 0)
	{
		int x = VAL0 << 4;
		int y = VAL0 >> 0xC;
		int z = x | y;
		int a = z ^ 0xA5;
		VAL0 = a;
		VAL0 = VAL0 + 0x25;

		// JMP loc_7FF78B083606
		for (int i = 0; i < 5; i++)
		{
			VAL0 = (VAL0 ^ (i * 0x17)) + 0x11;
		}

		// JMP loc_7FF78B083629
		VAL0 = VAL0 - 0x25;
		VAL0 = ((VAL0 >> 4) | (VAL0 << 0xC)) ^ 0xA5;
		VAL = VAL0;
	}

	int VAL1 = VAL;
	if (VAL % 5 == 0)
	{
		if (VAL % 3 == 0)
		{
			int x = VAL1 << 4;
			int y = VAL1 >> 0xC;
			int z = x | y;
			int a = z ^ 0xA5;
			VAL1 = a;
			VAL1 = VAL1 + 0x25;

			// JMP loc_7FF78B0836D1
			for (int i = 0; i < 5; i++)
			{
				VAL1 = (VAL1 ^ (i * 0x17)) + 0x11;
			}

			// JMP loc_7FF78B0836F4
			VAL1 = VAL1 - 0x25;
			VAL1 = ((VAL1 >> 4) | (VAL1 << 0xC)) ^ 0xA5;
			VAL = VAL1;

			for (int i = 0; i < 5; i++)
			{
				VAL = VAL << 1;
				int z = ((i & 1) ^ (VAL % 5)) - (VAL % 5);
				if (z == 0)
				{
					continue;
				}
				else
				{
					VAL = VAL + 0xA;
				}
			}
		}
		else
		{
			VAL = VAL - 0x2A;
			for (int i = 0; i < 5; i++)
			{
				VAL = VAL << 1;
				int z = ((i & 1) ^ (VAL % 3)) - (VAL % 3);
				if (z == 0)
				{
					continue;
				}
				else
				{
					VAL = VAL + 0xA;
				}
			}
		}
	}
	else
	{
		for (int i = 0; i < 5; i++)
		{
			VAL = VAL << 1;
			int z = ((i & 1) ^ (VAL % 5)) - (VAL % 5);
			if (z == 0)
			{
				continue;
			}
			else
			{
				VAL = VAL + 0xA;
			}
		}
	}

	int VAL_COPY = VAL;

	// 00007FF7D7ED38AF
	if (VAL_COPY % 7 == 0)
	{
		int VAL_COPY0 = VAL;
		VAL_COPY0 = ((VAL_COPY << 4) | (VAL_COPY >> 0xC)) ^ 0xA5;
		VAL_COPY0 = VAL_COPY0 + 0x25;

		// loc_7FF7D7ED3909
		for (int i = 0; i < 5; i++)
		{
			VAL_COPY0 = (VAL_COPY0 ^ (i * 0x17)) + 0x11;
		}

		// loc_7FF7D7ED392C
		VAL_COPY0 = VAL_COPY0 - 0x25;
		VAL_COPY0 = ((VAL_COPY0 >> 4) | (VAL_COPY0 << 0xC)) ^ 0xA5;
		VAL_COPY = VAL_COPY0;
	}

	// loc_7FF7D7ED395F
	int tmp = ((VAL_COPY & 1) ^ (VAL_COPY % 7)) - (VAL_COPY % 7);
	int RES_NEW = 0;
	if (tmp == 0)
	{
		int VAL_COPY0 = VAL_COPY - 0xA;
		VAL_COPY0 = ((VAL_COPY0 << 4) | (VAL_COPY0 >> 0xC)) ^ 0xA5;
		VAL_COPY0 = VAL_COPY0 + 0x25;

		// JMP loc_7FF7D7ED39BF
		for (int i = 0; i < 5; i++)
		{
			VAL_COPY0 = (VAL_COPY0 ^ (i * 0x17)) + 0x11;
		}

		// JMP loc_7FF7D7ED39E2
		VAL_COPY0 = VAL_COPY0 - 0x25;
		VAL_COPY0 = ((VAL_COPY0 >> 4) | (VAL_COPY0 << 0xC)) ^ 0xA5;
		RES_NEW = VAL_COPY0;

		// JMP loc_7FF7D7ED3AC2
	}
	else
	{
		// loc_7FF7D7ED3A1D
		int VAL_COPY0 = VAL_COPY + 0xA;
		VAL_COPY0 = ((VAL_COPY0 << 4) | (VAL_COPY0 >> 0xC)) ^ 0xA5;
		VAL_COPY0 = VAL_COPY0 + 0x25;

		// JMP loc_7FF7D7ED3A69
		for (int i = 0; i < 5; i++)
		{
			VAL_COPY0 = (VAL_COPY0 ^ (i * 0x17)) + 0x11;
		}

		// JMP loc_7FF7D7ED3A8C
		VAL_COPY0 = VAL_COPY0 - 0x25;
		VAL_COPY0 = ((VAL_COPY0 >> 4) | (VAL_COPY0 << 0xC)) ^ 0xA5;
		RES_NEW = VAL_COPY0;

		// JMP loc_7FF7D7ED3AC2
	}

	printf("Secret code: %u", RES_NEW);


	return 0;
}
```
