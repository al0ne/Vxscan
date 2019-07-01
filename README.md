English | [简体中文](./README.zh-CN.md)  
# Vxscan 1.0

Python3 comprehensive scanning tool, mainly used for sensitive file detection (directory scanning and js leak interface), WAF/CDN identification, port scanning, fingerprint/service identification, operating system identification, weak password detection, POC scanning, SQL injection, winding Pass CDN, check the next station

# Update
2019.7.1  
Display the host whose ping detection failed.  
The -u command can add multiple targets, separated by commas  
Fix fingerprint recognition error  
2019.6.18  
Fixed the problem of fingerprint recognition iis website error, modified apps.json   
Removed some third-party libraries and scripts that are prone to errors  
Scanning is completed if it flashes, it is because the program first detects dns parsing and ping operation.   
The first time you use Vxscan, fake_useragent will load the ua list of https://fake-useragent.herokuapp.com/browsers/0.1.11 here, and a load timeout error may occur.    

Requirements
--------

Python version > 3.6    
requests  
tqdm  
pyfiglet  
fake-useragent  
beautifulsoup4      
geoip2  
tldextract      
python-nmap  
geoip2  
tldextract  
lxml  
pymongo  
virustotal_python  
apt install libpq-dev nmap  
wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz  
After decompressing, put GeoLite2-City.mmdb inside to vxscan/db/GeoLite2-City.mmdb  
wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz  
After decompressing, put the GeoLite2-ASN.mmdb inside to vxscan/db/GeoLite2-ASN.mmdb  
pip3 install -r requirements.txt  

Features
--------
Generate a dictionary list using Cartesian product method, support custom dictionary list  
Random UserAgent, XFF, X-Real-IP  
Customize 404 page recognition, access random pages and then compare the similarities through difflib to identify custom 302 jumps  
When scanning the directory, first detect the http port and add multiple http ports of one host to the scan target.  
Filter invalid Content-Type, invalid status?  
WAF/CDN detection  
Use the socket to send packets to detect common ports and send different payload detection port service fingerprints.  
Hosts that encounter full port open (portspoof) automatically skip  
Call wappalyzer.json and WebEye to determine the website fingerprint  
It is detected that the CDN or WAF website automatically skips  
Call nmap to identify the operating system fingerprint  
Call weak password detection script based on port open (FTP/SSH/TELNET/Mysql/MSSQL...)  
Call POC scan based on fingerprint identification or port, or click on the open WEB port of IP  
Analyze sensitive asset information (domain name, mailbox, apikey, password, etc.) in the js file  
Grab website connections, test SQL injection, LFI, etc.  
Call some online interfaces to obtain information such as VT, www.yougetsignal.com and other websites, determine the real IP through VT pdns, and query the website by www.yougetsignal.com and api.hackertarget.com.     

Usage
--------
python3 Vxscan.py -h  
```
optional arguments:
  -h, --help            show this help message and exit  
  -u URL, --url URL     Start scanning this url -u xxx.com  
  -i INET, --inet INET  cidr eg. 1.1.1.1 or 1.1.1.0/24  
  -f FILE, --file FILE  read the url from the file  
  -t THREADS, --threads THREADS  
                        Set scan thread, default 150  
  -e EXT, --ext EXT     Set scan suffix, -e php,asp  
  -w WORD, --word WORD  Read the dict from the file  
```  

**1. Scan a website**  
```python3 vxscan.py -u http://www.xxx.com/ ```  
**2. Scan a website from a file list**  
```python3 vxscan.py -f hosts.txt```  
**3. cidr eg. 1.1.1.1 or 1.1.1.0/24**  
```python3 vxscan.py -i 127.0.0.0/24```  
**4. Set thread 100, combine only php suffix, use custom dictionary**  
```python3 vxscan.py -u http://www.xxx.com -e php -t 100 -w ../dict.txt```  

Structure
--------
```
/
├─Vxscan.py  main file
├─db
│  ├─apps.json  Web fingerprint information
│  ├─apps.txt  Web fingerprint information (WEBEYE)
│  ├─password.txt  password
├─report    Report directory
├─lib       
│  ├─common.py    Determine CDN, port scan, POC scan, etc.
│  ├─color.py   Terminal color output
│  ├─active.py   Judge dns parsing and ping ip survival
│  ├─save_html.py     Generate html report
│  ├─waf.py     waf rules
│  ├─osdetect.py   Operating system version identification
│  ├─random_header.py   random header
│  ├─scan_port.py        PortScan
│  ├─jsparse.py      Grab the website js connection, analyze ip address, link, email, etc.
│  ├─settings.py      Setting
│  ├─pyh.py     Generate html
│  ├─wappalyzer.py    Fingerprint recognition script
│  ├─sql_injection.py    Grab the website connection and test the SQL injection script
├─script  
│  ├─Poc.py         Poc script
│  ├─......
├─requirements.txt
├─logo.jpg
├─error.log

```

Waf/CDN list
--------
360  
360wzws  
Anquanbao  
Armor  
BaiduYunjiasu  
AWS WAF  
AdNovum  
Airee CDN  
Art of Defence HyperGuard  
ArvanCloud  
Barracuda NG  
Beluga CDN  
BinarySEC  
BlockDoS  
Bluedon IST  
CacheFly CDN  
ChinaCache CDN  
Cisco ACE XML Gateway  
CloudFlare CDN  
Cloudfront CDN  
Comodo  
CompState  
DenyALL WAF  
DenyAll  
Distil Firewall  
DoSArrest Internet Security  
F5 BIG-IP APM  
F5 BIG-IP ASM  
F5-TrafficShield  
Fastly CDN  
FortiWeb  
FortiWeb Firewall  
GoDaddy  
GreyWizard Firewall  
HuaweiCloudWAF  
HyperGuard Firewall  
IBM DataPower  
ISAServer  
Immunify360  
Imperva SecureSphere  
Incapsula CDN  
Jiasule  
KONA  
KeyCDN  
ModSecurity  
NGENIX CDN  
NSFOCUS  
Naxsi  
NetContinuum  
NetContinuum WAF  
Neusoft SEnginx  
Newdefend  
Palo Alto Firewall  
PerimeterX Firewall  
PowerCDN  
Profense  
Qiniu CDN  
Reblaze Firewall  
SDWAF  
Safe3  
Safedog  
SiteLock TrueShield  
SonicWALL  
SonicWall  
Sophos UTM Firewall  
Stingray  
Sucuri  
Teros WAF  
Usp-Sec  
Varnish  
Wallarm  
WatchGuard  
WebKnight  
West263CDN  
Yundun  
Yunsuo  
ZenEdge Firewall  
aesecure  
aliyun  
azion CDN  
cloudflare CDN  
dotDefender  
limelight CDN  
maxcdn CDN  
mod_security  
yunsuo  


Output
--------
The following is the AWVS scanner test website results    
![image](https://github.com/al0ne/A-hunter/raw/master/logo.jpg)
![image](https://github.com/al0ne/A-hunter/raw/master/logo2.jpg)

```

[
    {
        "testphp.vulnweb.com": {
            "WAF": "NoWAF",
            "Webinfo": {
                "apps": [
                    "Nginx",
                    "PHP",
                    "DreamWeaver",
                    "php"
                ],
                "title": "Home of Acunetix Art",
                "server": "nginx/1.4.1",
                "pdns": [
                    "176.28.50.165 : 2019-06-09 02:05:52"
                ],
                "reverseip": [
                    "176.28.50.165",
                    "rs202995.rs.hosteurope.de",
                    "testhtml5.vulnweb.com",
                    "testphp.ingensec.ch",
                    "testphp.ingensec.com",
                    "testphp.ingensec.fr",
                    "testphp.vulnweb.com",
                    "vulnweb.com",
                    "www.vulnweb.com"
                ]
            },
            "Ports": [
                "IMAPS:993",
                "ssh:22",
                "imap:143",
                "http:80",
                "Unknown:8880",
                "pop:110",
                "POP3:995",
                "smtp:25",
                "Unknown:8443",
                "SMTPS:465",
                "DNS:53",
                "ftp:21"
            ],
            "Ipaddr": "176.28.50.165",
            "Address": "德国  ",
            "Vuln": [
                "http://testphp.vulnweb.com | Home of Acunetix Art",
                "MySQL SQLi:http://testphp.vulnweb.com/search.php?test=query",
                "MySQL SQLi:http://testphp.vulnweb.com/artists.php?artist=1",
                "MySQL SQLi:http://testphp.vulnweb.com/listproducts.php?cat=2"
            ],
            "URLS": [
                {
                    "rsp_code": 200,
                    "rsp_len": 12473,
                    "title": "None",
                    "contype": "xml",
                    "url": "/.idea/workspace.xml"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 1,
                    "title": "None",
                    "contype": "plain",
                    "url": "/CVS/Root"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 4732,
                    "title": "search",
                    "contype": "html",
                    "url": "/search.php"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 1,
                    "title": "None",
                    "contype": "plain",
                    "url": "/CVS/Entries"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 3265,
                    "title": "Home of WASP Art",
                    "contype": "plain",
                    "url": "/index.bak"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 143,
                    "title": "None",
                    "contype": "xml",
                    "url": "/.idea/scopes/scope_settings.xml"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 3265,
                    "title": "Home of WASP Art",
                    "contype": "zip",
                    "url": "/index.zip"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 275,
                    "title": "None",
                    "contype": "xml",
                    "url": "/.idea/modules.xml"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 5523,
                    "title": "login page",
                    "contype": "html",
                    "url": "/login.php"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 278,
                    "title": "Index of /admin/",
                    "contype": "html",
                    "url": "/admin/"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 224,
                    "title": "None",
                    "contype": "xml",
                    "url": "/crossdomain.xml"
                },
                {
                    "rsp_code": 302,
                    "rsp_len": 14,
                    "title": "None",
                    "contype": "html",
                    "url": "/userinfo.php"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 6,
                    "title": "None",
                    "contype": "plain",
                    "url": "/.idea/.name"
                },
                {
                    "rsp_code": 200,
                    "rsp_len": 4958,
                    "title": "Home of Acunetix Art",
                    "contype": "html",
                    "url": "/index.php"
                }
            ]
        }
    }
]
```

Note
------
Reference cnnetarmy Srchunter design ideas  
Refer to the weak password module of brut3k1t:  
Https://github.com/ex0dus-0x/brut3k1t  
Fingerprint recognition mainly calls Wappalyzer and WebEye:  
https://github.com/b4ubles/python3-Wappalyzer  
https://github.com/zerokeeper/WebEye  
Poc referenced:  
BBscan scanner https://github.com/lijiejie/BBScan  
POC-T https://github.com/Xyntax/POC-T/tree/2.0/script  
Perun https://github.com/WyAtu/Perun  
Refer to the anthx port scan, service judgment:  
https://raw.githubusercontent.com/AnthraX1/InsightScan/master/scanner.py  
Injecting the crawler reference:  
DSSS https://github.com/stamparm/DSSS  
Js sensitive information regular extraction reference:  
https://github.com/nsonaniya2010/SubDomainizer  
WAF judges the use of waf00f and whatwaf judgment rules:  
https://github.com/EnableSecurity/wafw00f  
https://github.com/Ekultek/WhatWaf  
