---
title: Evil-Twin
categories: [Projects, Raspberry Pi]
---


# Overview
During my internship, I was given a raspberry pi to experiment with and was tasked to come up with something related to WiFi Pentesting. I wanted to find something that really intrigued me so began my research and found many interesting raspberry pi projects such as RubberDucky, Wi-Fi password cracking, hosting a phishing website, Evil Twin attacks. I decided to combine a few of the projects by creating an Evil-Twin access point with DNS poisoning that will redirect victims to a phishing website upon clicking a phishing website. 

# Evil-Twin
Evil Twin AP + DNS Poisoning

# What it does:
When victim connects to the Evil AP, upon clicking the phishing link, victim will be redirected to the phishing site attacker is hosting.

# How to use:
`Usage: ./evil.sh <Evil AP Name> <specify interface wireless interface> <web server ip addr>`

# Demo:
[![Evil-Twin demo](https://res.cloudinary.com/marcomontalbano/image/upload/v1642608373/video_to_markdown/images/streamable--13cpk4-c05b58ac6eb4c4700831b2b3070cd403.jpg)](https://streamable.com/13cpk4 "Evil-Twin demo")
