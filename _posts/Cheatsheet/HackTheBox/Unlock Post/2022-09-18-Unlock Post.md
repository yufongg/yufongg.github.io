---
title: HackTheBox - Unlock Password Protected Post
author: yufong
categories: [Cheatsheet]
date: 2022-09-18
img_path: /Cheatsheet/HackTheBox/Unlock Post/images/
image:
  src: Pasted%20image%2020220919012146.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Linux
1. Once you rooted the machine, have access `root` user
2. Obtain `root`'s hashed password
	```
	root@rooted-box:~# cat /etc/shadow | grep root | cut -d ":" -f2
	$y$j9T$zJMiBXFlQaVLqD8B7hPR3.$ceN5vvW/KTMQ.YeNjqT8UVo6TsKm/Dl8P1uefK6v5A1
	```
3. Enter the `hash` to unlock the post.