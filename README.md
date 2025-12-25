# CTF & Vulnerable Machine Writeups

A collection of detailed writeups for Capture The Flag (CTF) challenges and vulnerable machine penetration testing exercises.

## 📋 Contents

This repository contains writeups for the following machines:

### TryHackMe Challenges
- **[Blue](Blue.md)** - Windows machine exploiting EternalBlue (MS17-010) vulnerability
- **[Ignite](Ignite.md)** - Linux machine featuring Fuel CMS 1.4.1 remote code execution
- **[Lookup](Lookup.md)** - Linux machine involving username enumeration, elFinder exploitation, and PATH hijacking
- **[[Basic Pentesting]](Basic Pentesting.md)** - This is a machine that allows you to practise web app hacking and privilege escalation
- **[[Library]](Library.md)** - boot2root machine for FIT and bsides guatemala CTF

### VulnHub Machines
- **[RickdiculouslyEasy 1](RickdiculouslyEasy%201.md)** - Rick and Morty themed vulnerable machine with multiple flags (130 points)
- **[Dripping Blues](dripping%20blues.md)** - Linux machine featuring FTP enumeration and Polkit privilege escalation

## 🎯 Skills Demonstrated

These writeups cover various penetration testing techniques including:

- **Reconnaissance & Enumeration**
  - Nmap port scanning
  - Directory enumeration (Gobuster)
  - SMB/FTP enumeration
  - Username enumeration

- **Exploitation**
  - EternalBlue (MS17-010)
  - Remote Code Execution (RCE)
  - Command Injection
  - SQL Injection attempts

- **Privilege Escalation**
  - SUID binary exploitation
  - PATH hijacking
  - Sudo misconfigurations
  - Polkit (CVE-2021-3560)

- **Post-Exploitation**
  - File system navigation
  - Credential hunting
  - Flag retrieval
  - Lateral movement

## 🛠️ Tools Used

- **Scanning:** Nmap, arp-scan
- **Enumeration:** Gobuster, enum4linux, smbclient, crackmapexec
- **Exploitation:** Metasploit, Searchsploit, custom Python scripts
- **Password Cracking:** Hydra, John the Ripper, crunch
- **Privilege Escalation:** LinPEAS, custom exploits
- **Reverse Shells:** Netcat, Meterpreter

## 📝 Writeup Format

Each writeup follows a structured approach:

1. Initial reconnaissance and IP discovery
2. Port scanning and service enumeration
3. Web application analysis (where applicable)
4. Exploitation phase
5. Post-exploitation and privilege escalation
6. Flag capture and documentation

## 🔗 CTF Machine Links

- [Blue - Google Drive](https://drive.google.com/open?id=11f_wsW59Dh1fGvQCNUPK70lIWzlcg44_)
- [RickdiculouslyEasy - VulnHub](https://download.vulnhub.com/rickdiculouslyeasy/RickdiculouslyEasy.zip)
- [Dripping Blues - VulnHub](https://download.vulnhub.com/drippingblues/drippingblues.ova)
- [Lookup - TryHackMe](https://tryhackme.com/room/lookup)
- [Ignite - TryHackMe](https://tryhackme.com/room/ignite)
- [Basic Pentesting - TryHackMe](https://tryhackme.com/room/basicpentestingjt)
- [Library - TryHackMe](https://tryhackme.com/room/bsidesgtlibrary)

## ⚠️ Disclaimer

These writeups are for educational purposes only. All techniques demonstrated should only be used in authorized penetration testing environments or personal lab setups. Unauthorized access to computer systems is illegal.

## 📚 Learning Resources

These challenges are excellent for learning:
- Basic to intermediate penetration testing
- Linux and Windows privilege escalation
- Web application security
- Network enumeration techniques

---

**Author:** aswil192  
**Purpose:** Educational cybersecurity documentation
