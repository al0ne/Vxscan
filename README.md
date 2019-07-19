English | [简体中文](./README.zh-CN.md)  
# Vxscan 2.0

Python3 comprehensive scanning tool, mainly used for sensitive file detection (directory scanning and js leak interface), WAF/CDN identification, port scanning, fingerprint/service identification, operating system identification, weak password detection, POC scanning, SQL injection, winding Pass CDN, check the next station

# Update
2019.7.19  
Added socks5 global proxy  
Packaged requests  
Optimized directory structure  
Deleted the original html report, using the html report extracted from Perun  
Removed the json result output, adjusted to store in the sqllite3 database, deduplicate when warehousing, skip if the target host already exists in the db file during scanning  
Added phpinfo, leaves common information leak scanning plugin  
Pdns join the viewdns.info interface  
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
dnspython   
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
```  

**1. Scan a website**  
```python3 vxscan.py -u http://www.xxx.com/ ```  
**2. Scan a website from a file list**  
```python3 vxscan.py -f hosts.txt```  
**3. cidr eg. 1.1.1.1 or 1.1.1.0/24**  
```python3 vxscan.py -i 127.0.0.0/24```  

Structure
--------
```
├─Vxscan.py master file
├─db
│ ├─apps.json           Web fingerprint information
│ ├─apps.txt            Web fingerprint information (WEBEYE)
│ ├─GeoLite2-ASN.mmdb       geoip
│ ├─GeoLite2-City.mmdb      asn
├─doc                   to store some image or document resources
├─report                html report related content
├─lib
│ ├─common.py           Determine CDN, port scan, POC scan, etc.
│ ├─color.py            terminal color output
│ ├─cli_output.py       terminal output
│ ├─active.py to            judge dns resolution and ping ip survival
│ ├─save_html.py            Generate html reports
│ ├─waf.py              waf rules
│ ├─options.py          option settings
│ ├─iscdn.py            Determine whether IP is CDN based on ip segment and asn range
│ ├─osdetect.py         OS version identification
│ ├─random_header.py        custom header header
│ ├─settings.py         setting script
│ ├─vuln.py             Batch call POC scan
│ ├─url.py              Deduplicate the fetched connection
│ ├─verify.py           script provides verification interface
│ ├─sqldb.py            All related to sqlite3 are here
│ ├─Requests.py         packaged requests library, do some custom settings
├─script
│ ├─Poc.py Poc script
│ ├─......
├─Plugins
│ ├─ActiveReconnaissance
│   ├─active.py             to determine host survival and verify dns resolution
│   ├─check_waf.py          judge website waf
│   ├─crawk.py Crawl        website links and test
│   ├─osdetect.py           Operating System Identification
│ ├─InformationGathering
│   ├─geoip.py              Location Search
│   ├─js_leaks.py js        information disclosure
│ ├─PassiveReconnaissance
│   ├─ip_history.py         pdns interface
│   ├─reverse_domain.py         side station query
│   ├─virustotal.py         VT Pdns query
│   ├─wappalyzer.py         CMS passive fingerprint recognition
│ ├─Scanning
│   ├─dir_scan              directory scan
│   ├─port_scan             port scan
│ ├─Vulnerability
│   ├─lfi_sqli              Sql injection, LFI detection
├─requirements.txt
├─report.py html            report generation
├─logo.jpg
├─error.log

```


SETTING
--------
```python
# coding=utf-8

# global timeout
TIMEOUT = 5

# Is the status to be excluded
BLOCK_CODE = [
    301, 403, 308, 404, 405, 406, 408, 411, 417, 429, 493, 502, 503, 504, 999
]
# Set scan thread
THREADS = 100
# Content type to exclude
BLOCK_CONTYPE = [
    'image/jpeg', 'image/gif', 'image/png', 'application/javascript',
    'application/x-javascript', 'text/css', 'application/x-shockwave-flash',
    'text/javascript', 'image/x-icon'
]

# Whether to skip directory scanning
SCANDIR = True

# Whether to start the POC plugin
POC = True

# Skip if it exists in the result db
CHECK_DB = False

# invalid 404 page
PAGE_404 = [
    'page_404"', "404.png", '找不到页面', '页面找不到', "Not Found", "访问的页面不存在",
    "page does't exist", 'notice_404', '404 not found', '<title>错误</title>', '内容正在加载', '提示：发生错误', '<title>网站防火墙',
    '无法加载控制器'
]

# ping
PING = True

# socks5 proxy
# SOCKS5 = ('127.0.0.1', 1080)
SOCKS5 = ()

# shodan
SHODAN_API = ''

# VT
VIRUSTOTAL_API = ''

# cookie
COOKIE = {'Cookie': 'test'}
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


Note
------
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
The html report uses: 
https://github.com/WyAtu/Perun
https://github.com/ly1102 