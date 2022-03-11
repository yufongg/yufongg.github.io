---
title: Spydersec - Challenge
categories: [Vulnhub, Linux]
date: 2022-02-06 
tags: [cryptography]
img_path: /Writeups/Vulnhub/Linux/Spydersec - Challenge/images/
image:
  src: Pasted%20image%2020220311165850.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Recon

## TCP/80 (HTTP)
### FFUF
```
┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/loot/http]
└─# ffuf -u http://192.168.110.38/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php,.log,.bak'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.38/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php .log .bak 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.html                   [Status: 403, Size: 271, Words: 20, Lines: 11]
.hta                    [Status: 403, Size: 270, Words: 20, Lines: 11]
.hta.html               [Status: 403, Size: 275, Words: 20, Lines: 11]
.hta.php                [Status: 403, Size: 274, Words: 20, Lines: 11]
.htaccess.txt           [Status: 403, Size: 279, Words: 20, Lines: 11]
.hta.log                [Status: 403, Size: 274, Words: 20, Lines: 11]
.hta.txt                [Status: 403, Size: 274, Words: 20, Lines: 11]
.htaccess.html          [Status: 403, Size: 280, Words: 20, Lines: 11]
.htaccess.log           [Status: 403, Size: 279, Words: 20, Lines: 11]
.htaccess.bak           [Status: 403, Size: 279, Words: 20, Lines: 11]
.htpasswd.txt           [Status: 403, Size: 279, Words: 20, Lines: 11]
.htpasswd               [Status: 403, Size: 275, Words: 20, Lines: 11]
.htaccess.php           [Status: 403, Size: 279, Words: 20, Lines: 11]
.htpasswd.php           [Status: 403, Size: 279, Words: 20, Lines: 11]
.htpasswd.log           [Status: 403, Size: 279, Words: 20, Lines: 11]
.hta.bak                [Status: 403, Size: 274, Words: 20, Lines: 11]
.htpasswd.bak           [Status: 403, Size: 279, Words: 20, Lines: 11]
.htaccess               [Status: 403, Size: 275, Words: 20, Lines: 11]
.htpasswd.html          [Status: 403, Size: 280, Words: 20, Lines: 11]
                        [Status: 200, Size: 8883, Words: 800, Lines: 33]
favicon.ico             [Status: 200, Size: 1150, Words: 132, Lines: 1]
index.php               [Status: 200, Size: 8883, Words: 800, Lines: 33]
index.php               [Status: 200, Size: 8883, Words: 800, Lines: 33]
v                       [Status: 301, Size: 296, Words: 19, Lines: 10]
:: Progress: [27690/27690] :: Job [1/1] :: 1005 req/sec :: Duration: [0:00:38] :: Errors: 0 ::
```
- `v`

# Initial Foothold

## TCP/80 (HTTP) - Clue 1
1. Proceed to `index.html`
	![](Pasted%20image%2020220311005220.png)
	> "Find clues on this webpage"
2. Found suspicious javascript on the page source
	- Suspicious javascript
		``` javascript
		<script>
		eval(function(p,a,c,k,e,d){e=function(c){return c.toString(36)};if(!''.replace(/^/,String)){while(c--){d[c.toString(a)]=k[c]||c.toString(a)}k=[function(e){return d[e]}];e=function(){return'\\w+'};c=1};while(c--){if(k[c]){p=p.replace(new RegExp('\\b'+e(c)+'\\b','g'),k[c])}}return p}('7:0:1:2:8:6:3:5:4:0:a:1:2:d:c:b:f:3:9:e',16,16,'6c|65|72|27|75|6d|28|61|74|29|64|62|66|2e|3b|69'.split('|'),0,{}))
		</script>
		```
		![](Pasted%20image%2020220311153735.png)
3. Use [javascript unpacker](https://matthewfl.com/unPacker.html) to deobfuscate/unpack/beautify the javascript code
>JavaScript Unpacker is **a useful client-side online tool to unpack/ beautify/ deobfuscate your packed JavaScript code**. If your JavaScript code looks like: eval(function (p,a,c,k,e,d){...}...)eval(function(p,a,c,k,e,r){...}...). Using this tool, you are able to deobfuscate, beautify, unpack your javascript code
![](Pasted%20image%2020220311154930.png)
4. Decode it
	``` 
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/loot/http]
	└─# echo -n 61:6c:65:72:74:28:27:6d:75:6c:64:65:72:2e:66:62:69:27:29:3b | xxd -r -p
	alert('mulder.fbi');
	```
	
## TCP/80 (HTTP) - Clue 2
5. `Inspect Element -> Sources` & download images on the website
	``` 
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/loot/http]
	└─# wget -q http://192.168.110.38/SpyderSecLogo200.png
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/loot/http]
	└─# wget -q http://192.168.110.38/Challenge.png
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/loot/http]
	└─# wget -q http://192.168.110.38/BG.jpg
	```
6. Analyze the images to look for clues
	``` 
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/loot/http]
	└─# exiftool *
	======== BG.jpg
	ExifTool Version Number         : 12.39
	File Name                       : BG.jpg
	Directory                       : .
	File Size                       : 265 KiB
	File Modification Date/Time     : 2015:09:01 14:17:17+08:00
	File Access Date/Time           : 2022:03:11 00:56:07+08:00
	File Inode Change Date/Time     : 2022:03:11 00:56:07+08:00
	File Permissions                : -rw-r--r--
	File Type                       : JPEG
	File Type Extension             : jpg
	MIME Type                       : image/jpeg
	Exif Byte Order                 : Little-endian (Intel, II)
	Quality                         : 50%
	DCT Encode Version              : 100
	APP14 Flags 0                   : [14], Encoded with Blend=1 downsampling
	APP14 Flags 1                   : (none)
	Color Transform                 : YCbCr
	Image Width                     : 1920
	Image Height                    : 1849
	Encoding Process                : Progressive DCT, Huffman coding
	Bits Per Sample                 : 8
	Color Components                : 3
	Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
	Image Size                      : 1920x1849
	Megapixels                      : 3.6
	======== Challenge.png
	ExifTool Version Number         : 12.39
	File Name                       : Challenge.png
	Directory                       : .
	File Size                       : 83 KiB
	File Modification Date/Time     : 2015:09:01 14:25:59+08:00
	File Access Date/Time           : 2022:03:11 00:55:58+08:00
	File Inode Change Date/Time     : 2022:03:11 00:55:58+08:00
	File Permissions                : -rw-r--r--
	File Type                       : PNG
	File Type Extension             : png
	MIME Type                       : image/png
	Image Width                     : 540
	Image Height                    : 540
	Bit Depth                       : 8
	Color Type                      : RGB with Alpha
	Compression                     : Deflate/Inflate
	Filter                          : Adaptive
	Interlace                       : Noninterlaced
	Background Color                : 255 255 255
	Pixels Per Unit X               : 2835
	Pixels Per Unit Y               : 2835
	Pixel Units                     : meters
	Comment                         : 35:31:3a:35:33:3a:34:36:3a:35:37:3a:36:34:3a:35:38:3a:33:35:3a:37:31:3a:36:34:3a:34:35:3a:36:37:3a:36:61:3a:34:65:3a:37:61:3a:34:39:3a:33:35:3a:36:33:3a:33:30:3a:37:38:3a:34:32:3a:34:66:3a:33:32:3a:36:37:3a:33:30:3a:34:61:3a:35:31:3a:33:64:3a:33:64
	Image Size                      : 540x540
	Megapixels                      : 0.292
	======== SpyderSecLogo200.png
	ExifTool Version Number         : 12.39
	File Name                       : SpyderSecLogo200.png
	Directory                       : .
	File Size                       : 25 KiB
	File Modification Date/Time     : 2015:09:01 14:17:17+08:00
	File Access Date/Time           : 2022:03:11 00:55:51+08:00
	File Inode Change Date/Time     : 2022:03:11 00:55:51+08:00
	File Permissions                : -rw-r--r--
	File Type                       : PNG
	File Type Extension             : png
	MIME Type                       : image/png
	Image Width                     : 200
	Image Height                    : 200
	Bit Depth                       : 8
	Color Type                      : RGB with Alpha
	Compression                     : Deflate/Inflate
	Filter                          : Adaptive
	Interlace                       : Noninterlaced
	Significant Bits                : 8 8 8 8
	Pixels Per Unit X               : 599
	Pixels Per Unit Y               : 599
	Pixel Units                     : meters
	Software                        : www.inkscape.org
	Image Size                      : 200x200
	Megapixels                      : 0.040
		3 image files read
	```
	- `Challenge.png` has an interesting comment, looks like hexadecmial
6. Decode it
	``` 
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/loot/http]
	└─# echo -n 35:31:3a:35:33:3a:34:36:3a:35:37:3a:36:34:3a:35:38:3a:33:35:3a:37:31:3a:36:34:3a:34:35:3a:36:37:3a:36:61:3a:34:65:3a:37:61:3a:34:39:3a:33:35:3a:36:33:3a:33:30:3a:37:38:3a:34:32:3a:34:66:3a:33:32:3a:36:37:3a:33:30:3a:34:61:3a:35:31:3a:33:64:3a:33:64 | xxd -r -p | xxd -r -p | base64 -d
	A!Vu~jtH#729sLA;h4%
	```
	- Ciphertext is hexadecimal encoded twice & base64 encoded once.

## TCP/80 (HTTP) - Clue 3
1. Reload page & intercept w/ burpsuite
	![](Pasted%20image%2020220311155844.png)
	- URL Encoded
2. Decode it
	``` 
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/loot/http]
	└─# hURL -u %2Fv%2F81JHPbvyEQ8729161jd6aKQ0N4%2F

	Original    :: %2Fv%2F81JHPbvyEQ8729161jd6aKQ0N4%2F
	URL DEcoded :: /v/81JHPbvyEQ8729161jd6aKQ0N4/
	```

## TCP/80 (HTTP) - Connecting the dots
1. Proceed to `/v/81JHPbvyEQ8729161jd6aKQ0N4/` (Clue 3)
	![](Pasted%20image%2020220311161816.png)
	- 403 Forbidden
2. Proceed to  `/v/81JHPbvyEQ8729161jd6aKQ0N4/mulder.fbi` (Clue 1) 
	![](Pasted%20image%2020220311161920.png)
	- `mulder.fbi` is downloaded
3. Analyze mulder.fbi 
	``` 
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/loot/http]
	└─# file mulder.fbi 
	mulder.fbi: ISO Media, MP4 v2 [ISO 14496-14]
	```
	- `MP4`
	- Since this is a CTF challenge, it is likely a `MP4` steganography
4. Research on MP4 steganography
	- [Truecrypt volume can be hidden in a MP4 file](https://appliedtech.iit.edu/school-applied-technology/projects/mp4-steganography)
	- [TCSteg Download](https://raw.githubusercontent.com/joshualat/CS-198-Web-API-Project/master/usb_programs/tcsteg.py)
	> TCSteg allows users to hide a TrueCrypt hidden volume in an MP4 file, and the structure of the file makes it difficult to identify that a volume exists
5. Uncover the hidden Truecrypt volume
	``` 
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/exploit]
	└─# python tcsteg2.py 
	too few arguments
	Usage (1): tcsteg2.py <MP4 Video> <TrueCrypt Container>
	Embeds a file into a TrueCrypt container so that both are still readable.

	<MP4 Video> is a file in one of the following formats:
	   QuickTime / ISO MPEG-4  (*.mov, *.qt, *.mp4, *.m4v, *.m4a, *.3gp)

	<TrueCrypt Container> is a TrueCrypt hidden volume. The file will be
	modified in-place so that it seems like a copy of the input file that can be
	opened in an appropriate viewer/player. However, the hidden TrueCtype volume
	will also be preserved and can be used.


	Usage (2): tcsteg2.py -p <Hybrid File>
	<Hybrid File> is a file that is both TrueCrypt container and a video.
	This file will be modified in-place to make it possible to change the TrueCrypt
	password. After changing the password, this command should be run again to
	remove that (detectable and hence insecure) modification!

	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/exploit]
	└─# mv mulder.fbi mulder.mp4


	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/exploit]
	└─# python tcsteg2.py -p mulder.mp4
	Preparing hybrid file for password change ... 
	Complete.  Now change the TrueCrypt password

	```
6. Mount truecrypt volume w/ 'A!Vu~jtH#729sLA;h4%' (Clue 2)
	``` 
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/exploit]
	└─# veracrypt -tc mulder.fbi truecrypt_volume/ 
	Enter password for /root/vulnHub/Spydersec/192.168.110.38/exploit/mulder.fbi: A!Vu~jtH#729sLA;h4%
	Enter keyfile [none]: 
	Protect hidden volume (if any)? (y=Yes/n=No) [No]: 
	```
7. Flag
	``` 
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/exploit]
	└─# cd truecrypt_volume/
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/exploit/truecrypt_volume]
	└─# ls
	Flag.txt
	┌──(root💀kali)-[~/vulnHub/Spydersec/192.168.110.38/exploit/truecrypt_volume]
	└─# cat Flag.txt 
	Congratulations! 

	You are a winner. 

	Please leave some feedback on your thoughts regarding this challenge� Was it fun? Was it hard enough or too easy? What did you like or dislike, what could be done better?

	https://www.spydersec.com/feedback
	```





