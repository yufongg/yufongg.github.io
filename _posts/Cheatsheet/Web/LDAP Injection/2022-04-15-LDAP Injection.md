---
title: Cheatsheet - LDAP Injection
categories: [Cheatsheet, Web]
tags: [cheatsheet/web, exploit/ldap-injection]
img_path: /Cheatsheet/Web/LDAP Injection/images
---

# LDAP Injection
-  Determine if `admin.php` is susceptible to LDAP Injection, since `TCP/389,636 - LDAP` is up
	- [LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection) is an attack used to exploit web based applications that construct LDAP statements based on user input, when fails to properly sanitize user input, it’s possible to modify LDAP statements to bypass login, execute commands.
	- Setup
- Wordlist
	```
	/usr/share/wordlists/ldap_injection/ldap_injection.txt
	```
- Some Examples:
	- [Vulnhub Symfonos 5.2 - LDAP Injection](https://yufongg.github.io/posts/Symfonos-5.2/#tcp80-http---ldap-injection)


# Extract everything from a Domain
```
ldapsearch -x -h <IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TDL>"
```

# Reference
- https://book.hacktricks.xyz/pentesting/pentesting-ldap#manual-1
- https://book.hacktricks.xyz/pentesting-web/ldap-injection


---
Tags: 

---