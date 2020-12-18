---
title: '[XMAS CTF 2020] Ministerul Mediului, Apelor și Pădurilor'
published: true
tags: [writeup, pwn, mmap]
author: neo & En3rRe
---

Challenge description:

```
I thought that mmap-ing memory is safer than using malloc, so safe that I don't even need to enforce security checks. Well, I got it very very wrong.

Confused about the title? Google is too: https://imgur.com/a/QsSt41g

Update: If you exploit was working locally, but not on the remote, now it should work. I fixed the reading.
Update: The flag is in /home/ctf/flag.txt (and for all other challenges)

Running on Ubuntu 20.04

Target: nc challs.xmas.htsp.ro 2003
Author: littlewho
```
