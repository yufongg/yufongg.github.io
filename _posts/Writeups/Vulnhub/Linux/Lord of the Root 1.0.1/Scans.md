# NMAP Complete Scan
```
# Nmap 7.92 scan initiated Mon Jan 24 21:19:30 2022 as: nmap -vv --reason -Pn -T4 -sV -p 22 --script=banner,ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -oN /root/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/scans/tcp22/tcp_22_ssh_nmap.txt -oX /root/vulnHub/Lord-of-the-root-1.0.1/192.168.236.10/scans/tcp22/xml/tcp_22_ssh_nmap.xml 192.168.236.10
Nmap scan report for 192.168.236.10
Host is up, received arp-response (0.00034s latency).
Scanned at 2022-01-24 21:19:30 +08 for 1s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.3 (Ubuntu Linux; protocol 2.0)
|_banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3
| ssh-hostkey: 
|   1024 3c:3d:e3:8e:35:f9:da:74:20:ef:aa:49:4a:1d:ed:dd (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAJKVpy10olbGC8nI2MWPTGKXhT6VsZcRnCAjQhqcpe8hLZ4cXu33YaLzgHJF1cm0ebDTZNP55kkYx8iQLw4izWfw21R45GWEuFLa6gX7wsygffXlSP0jlGbnspYWZj9FkbqN8GOFnUsqvCDCcXDe69OlxGPhBiMxB1rxuoUZnxPZAAAAFQCDbd7sa658iDpIzFLRsbyEkgmvQwAAAIA4myZvSg9MIJQoio8r7Pu2Z7de6aMg6dooumuVPfbsvcb1ZpcnU1nnBcJe5sSof/eIZSqh+NFl3r04rVcNmEMNP+7liXhjGAQ4G0c95vAN+12V12vHdk2YXEO4Mj/VhQxI1AP/5XdiY4OI7vDVY6FGw+4gR+aarZIDjY67jpl//QAAAIAvQVESJOOiTImUdavfNImDDFo/8Ttw0Iq9OcAwuE3umJ6PSfjcTq5IODKQ1hHr8Qb/+7Q6+osumyd6ONOIuM9x8sWExOAlWrcGkZszDzBUb4tjWXdliHuxYds+qZjl3esaKbeW5v97Zf5RPYeUv7cWWxThqbVNehp+fsxAmhMhgw==
|   2048 85:94:6c:87:c9:a8:35:0f:2c:db:bb:c1:3f:2a:50:c1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZnR9vNmnhJVAXLzEz9KbyuNunmOeZLgWAvEXrYL5PQUSnjV6r9quuRtcjxs26JAMkSr2GH0r8JEhYKQQBMdGe7j/qfN5gorUOykWv1R3v+4Blu5L4R+8v7pFrQnu7IrAbms9fOiiF0nCWs6dugDQ+4rBl+90WHbJ40s5f9L1akGBpYmuuT9gy7ULabvc6CYZ2+cCFVpkf/s8rc3z3OV0W5JNoENyXtyvuirQqQ4+xLVlyPFpBfmqx1mY1XOeY7qqN99/82Ti9JfNJwjWgINGTY0wWGuWJdYrxAiyL/F9/MPJyb/zEM9I2/ne+qUrJ1Jkpcl4eJ42UV7HUkUGpZXkb
|   256 f3:cd:aa:1d:05:f2:1e:8c:61:87:25:b6:f4:34:45:37 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFoWH4DDWVRbA1EqnCjoMMCx5bR9hiI5qTJIi+LGY9kWZQU4Y4D+MJQRoDBVd/ijYLAQ1HvW/MZIpjRCfUON6uU=
|   256 34:ec:16:dd:a7:cf:2a:86:45:ec:65:ea:05:43:89:21 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK8+Q9UBYlSuxYmR6fYF4W8Vv22fP15QxiCfpGk8JV2+
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|_    password
| ssh2-enum-algos: 
|   kex_algorithms: (8)
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group-exchange-sha1
|       diffie-hellman-group14-sha1
|       diffie-hellman-group1-sha1
|   server_host_key_algorithms: (4)
|       ssh-rsa
|       ssh-dss
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (16)
|       aes128-ctr
|       aes192-ctr
|       aes256-ctr
|       arcfour256
|       arcfour128
|       aes128-gcm@openssh.com
|       aes256-gcm@openssh.com
|       chacha20-poly1305@openssh.com
|       aes128-cbc
|       3des-cbc
|       blowfish-cbc
|       cast128-cbc
|       aes192-cbc
|       aes256-cbc
|       arcfour
|       rijndael-cbc@lysator.liu.se
|   mac_algorithms: (19)
|       hmac-md5-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-64-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-ripemd160-etm@openssh.com
|       hmac-sha1-96-etm@openssh.com
|       hmac-md5-96-etm@openssh.com
|       hmac-md5
|       hmac-sha1
|       umac-64@openssh.com
|       umac-128@openssh.com
|       hmac-sha2-256
|       hmac-sha2-512
|       hmac-ripemd160
|       hmac-ripemd160@openssh.com
|       hmac-sha1-96
|       hmac-md5-96
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
MAC Address: 08:00:27:FF:4B:98 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 24 21:19:31 2022 -- 1 IP address (1 host up) scanned in 0.71 seconds

```