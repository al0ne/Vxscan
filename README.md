# Vxscan 1.0

python3写的综合扫描工具，主要用来敏感文件探测(目录扫描与js泄露接口)，WAF/CDN识别，端口扫描，指纹/服务识别，操作系统识别，弱口令探测，POC扫描，SQL注入，绕过CDN，查询旁站等功能，主要用来甲方自测或乙方授权测试，请勿用来搞破坏。

# Update
2019.6.18  
修复了指纹识别iis网站报错的问题，修改了apps.json  
删除了一些容易引起错误的第三方库与脚本  

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
解压后将里面的GeoLite2-City.mmdb放到vxscan/db/GeoLite2-City.mmdb  
wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz  
解压后将里面的GeoLite2-ASN.mmdb放到vxscan/db/GeoLite2-ASN.mmdb  
pip3 install -r requirements.txt  

Features
--------
使用笛卡尔乘积方式生成字典列表，支持自定义字典列表  
随机的UserAgent、XFF、X-Real-IP  
自定义404页面识别，访问随机页面然后通过difflib对比相似度，识别自定义302跳转  
扫描目录时先探测http端口，将一个主机多个http端口加入到扫描目标中  
过滤无效Content-Type，无效状态吗  
WAF/CDN探测  
使用socket发包探测常见端口，发送不同payload探测端口服务指纹   
遇到全端口开放的主机(portspoof)自动跳过   
调用wappalyzer.json与WebEye判断网站指纹   
检测到CDN或者WAF网站自动跳过  
调用nmap识别操作系统指纹  
根据端口开放调用弱口令探测脚本(FTP/SSH/TELNET/Mysql/MSSQL...)  
根据指纹识别或者端口调用POC扫描,或将IP开放的WEB端口上打一遍     
分析js文件里面的敏感资产信息(域名、邮箱、apikey、password等)   
抓取网站连接，测试SQL注入，LFI等  
调用一些在线接口获取信息例如VT、www.yougetsignal.com等网站，通过VT pdns判断真实IP,通过www.yougetsignal.com、api.hackertarget.com查询网站旁站      

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

**1. 扫描一个网站**  
```python3 vxscan.py -u http://www.xxx.com/ ```  
**2. 从文件列表里扫描网站**  
```python3 vxscan.py -f hosts.txt```  
**3. 扫描一个C段**  
```python3 vxscan.py -i 127.0.0.0/24```  
**4. 设置线程100,组合只用php后缀，使用自定义字典**  
```python3 vxscan.py -u http://www.xxx.com -e php -t 100 -w ../dict.txt```  

Structure
--------
```
/
├─Vxscan.py  主文件
├─db
│  ├─apps.json  Web指纹信息
│  ├─apps.txt  Web指纹信息(WEBEYE)
│  ├─password.txt  密码字典
├─report    报告目录
├─lib       
│  ├─common.py    判断CDN、端口扫描、POC扫描等
│  ├─color.py   终端颜色输出
│  ├─active.py   判断dns解析与ping ip存活
│  ├─save_html.py     生成html报表
│  ├─waf.py     waf规则
│  ├─osdetect.py   操作系统版本识别
│  ├─random_header.py   自定义header头
│  ├─scan_port.py        端口扫描脚本
│  ├─jsparse.py      抓取网站js连接，分析ip地址，链接，Email等
│  ├─settings.py      设置脚本
│  ├─pyh.py     生成html
│  ├─wappalyzer.py    指纹识别脚本
│  ├─sql_injection.py    抓取网站连接，测试SQL注入脚本
├─script  
│  ├─Poc.py         Poc脚本
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
以下是AWVS扫描器测试网站结果  
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
参考了cnnetarmy Srchunter设计思路  
参考了brut3k1t的弱口令模块：  
https://github.com/ex0dus-0x/brut3k1t  
指纹识别主要调用Wappalyzer与WebEye：  
https://github.com/b4ubles/python3-Wappalyzer  
https://github.com/zerokeeper/WebEye  
Poc参考了:  
BBscan扫描器 https://github.com/lijiejie/BBScan  
POC-T https://github.com/Xyntax/POC-T/tree/2.0/script  
Perun https://github.com/WyAtu/Perun   
参考了anthx的端口扫描、服务判断：
https://raw.githubusercontent.com/AnthraX1/InsightScan/master/scanner.py  
注入爬虫参考了：  
DSSS https://github.com/stamparm/DSSS  
js敏感信息正则提取参考了：  
https://github.com/nsonaniya2010/SubDomainizer  
WAF判断使用的是waf00f与whatwaf的判断规则：  
https://github.com/EnableSecurity/wafw00f  
https://github.com/Ekultek/WhatWaf   
 
**请使用者遵守《中华人民共和国网络安全法》，勿用于非授权测试，如作他用所承受的法律责任一概与作者无关，下载使用即代表使用者同意上述观点**。
