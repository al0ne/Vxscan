# Vxscan 2.0

[![Build Status](https://api.travis-ci.org/al0ne/Vxscan.svg?branch=master)](https://travis-ci.org/al0ne/Vxscan)
[![ISSUE](https://img.shields.io/github/issues/al0ne/Vxscan)](https://github.com/al0ne/Vxscan/issues)
[![star](https://img.shields.io/github/stars/al0ne/Vxscan)](./)
[![license](https://img.shields.io/github/license/al0ne/Vxscan)](https://github.com/al0ne/Vxscan/blob/master/LICENSE)
[![python](https://img.shields.io/badge/python-3.6%20%7C%203.7%20%7C%203.8-blue)](./)  

[English](./README.md) | 简体中文  

python3写的综合扫描工具，主要用来敏感文件探测(目录扫描与js泄露接口)，WAF/CDN识别，端口扫描，指纹/服务识别，弱口令探测，POC扫描，SQL注入等功能。

# Update  

2019.7.19  
添加了socks5全局代理
封装了requests  
优化了目录结构  
删除了原来html报告，采用了从Perun里抽取的html报表  
去掉了json结果输出，调整为存储到sqllite3数据库中，入库时进行去重，扫描时如果目标主机已存在db文件中则跳过  
添加了phpinfo、leaks常见的信息泄露扫描插件  
pdns加入viewdns.info接口    
2019.7.1  
显示ping检测失败的主机  
-u 命令可以添加多个目标，用逗号隔开  
修复指纹识别报错问题  
2019.6.18  
修复了指纹识别iis网站报错的问题，修改了apps.json  
删除了一些容易引起错误的第三方库与脚本  
扫描如果出现一闪而过就完成，那是因为程序首先检测dns解析与ping操作  
第一次用Vxscan时，fake_useragent会加载这里的 https://fake-useragent.herokuapp.com/browsers/0.1.11 的ua列表，可能会出现加载超时错误

Requirements
--------

Python version > 3.6    
requests  
pyfiglet  
fake-useragent  
beautifulsoup4  
geoip2  
tldextract  
pymysql  
pymssql  
python-nmap  
geoip2  
tldextract  
lxml  
pymongo  
psycopg2  
virustotal_python  
dnspython  
paramiko  
cryptography==2.4.2  

apt install libpq-dev nmap  

wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz  
After decompressing, put GeoLite2-City.mmdb inside to vxscan/data/GeoLite2-City.mmdb  

wget https://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz  
After decompressing, put the GeoLite2-ASN.mmdb inside to vxscan/data/GeoLite2-ASN.mmdb  

pip3 install -r requirements.txt 

Features
--------
 - Webinfo
    + GeoIP
    + DNS 解析验证
    + Ping 存活验证
    - WAF/CDN 探测
        + WAF Rules
        + CDN IP段
        + CDN ASN
    + HTTP 标题
    + HTTP Server
    + HTTP Headers
    - 指纹识别
        + Wappalyzer
        + WEBEYE
    - PDNS
        + virustotal
        + viewdns.info
    - 旁站查询
        + yougetsignal.com
        + api.hackertarget.com
    + 操作系统版本探测 (nmap)
 - Ports
    + 400+ Ports
    + 跳过CDN IP
    + 全端口开放的主机(portspoof)自动跳过
 - URLS
    + 常见备份、后门、目录、中间件、敏感文件地址
    + 使用笛卡尔乘积方式生成字典列表
    + 随机的UserAgent、XFF、X-Real-IP、Referer
    + 自定义404页面识别 (页面相似度、页面关键词)
    + 识别自定义302跳转
    + 过滤无效Content-Type，无效状态吗
    + 保存url、title、contype、rsp_len、rsp_code
 - Vuln
    + 将一个主机多个HTTP端口加入POC目标
    + 根据指纹、端口服务来调用POC
    + 未授权、反序列化、RCE、Sqli...
 - Report
    + 结果存入Sqlite3数据库
    + 入库去重，检测到已有项目将不在扫描
    + 生成html报告
   

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

**1. 扫描一个网站**  
```python3 vxscan.py -u http://www.xxx.com/ ```  
**2. 从文件列表里扫描网站**  
```python3 vxscan.py -f hosts.txt```  
**3. 扫描一个C段**  
```python3 vxscan.py -i 127.0.0.0/24```  

Structure
--------
```
/
├─Vxscan.py  主文件
├─data
│  ├─apps.json  Web指纹信息
│  ├─apps.txt  Web指纹信息(WEBEYE)
│  ├─GeoLite2-ASN.mmdb      geoip
│  ├─GeoLite2-City.mmdb     asn
├─doc    存放一些图片或者文档资源
├─report    html报告相关内容
├─lib       
│  ├─common.py    判断CDN、端口扫描、POC扫描等
│  ├─color.py    终端颜色输出
│  ├─cli_output.py   终端输出
│  ├─active.py   判断dns解析与ping ip存活
│  ├─save_html.py     生成html报表
│  ├─waf.py     waf规则
│  ├─options.py     选项设置
│  ├─iscdn.py     根据ip段和asn范围来判断IP是不是CDN
│  ├─osdetect.py   操作系统版本识别
│  ├─random_header.py   自定义header头
│  ├─settings.py      设置脚本
│  ├─vuln.py      批量调用POC扫描
│  ├─url.py     对抓取的连接进行去重
│  ├─verify.py     script脚本提供验证接口
│  ├─sqldb.py      所有与sqlite3有关的都在这里
│  ├─Requests.py   封装的requests库，做一些自定义设置
├─script  
│  ├─Poc.py         Poc脚本
│  ├─......
├─Plugins
│  ├─ActiveReconnaissance
│    ├─active.py         判断主机存活并且验证dns解析
│    ├─check_waf.py      判断网站waf
│    ├─crawk.py         抓取网站连接并测试
│    ├─osdetect.py      操作系统识别
│  ├─InformationGathering
│    ├─geoip.py         地理位置查询
│    ├─js_leaks.py      js信息泄露
│  ├─PassiveReconnaissance
│    ├─ip_history.py        pdns接口
│    ├─reverse_domain.py    旁站查询
│    ├─virustotal.py        VT Pdns查询
│    ├─wappalyzer.py      CMS被动指纹识别
│  ├─Scanning
│    ├─dir_scan     目录扫描
│    ├─port_scan    端口扫描
│  ├─Vulnerability
│    ├─lfi_sqli     Sql注入、LFI检测
├─requirements.txt
├─report.py         html 报告生成
├─logo.jpg
├─error.log

```
SETTING
--------
```python
# coding=utf-8

# 全局超时时间
TIMEOUT = 5

# 要排除的状态吗
BLOCK_CODE = [
    301, 403, 308, 404, 405, 406, 408, 411, 417, 429, 493, 502, 503, 504, 999
]
# 设置扫描线程
THREADS = 100
# 要排除的 内容类型
BLOCK_CONTYPE = [
    'image/jpeg', 'image/gif', 'image/png', 'application/javascript',
    'application/x-javascript', 'text/css', 'application/x-shockwave-flash',
    'text/javascript', 'image/x-icon'
]

# 是否跳过目录扫描
SCANDIR = True

# 是否启动POC插件
POC = True

# 如果存在于结果db中就跳过
CHECK_DB = False

# 无效的404页面
PAGE_404 = [
    'page_404"', "404.png", '找不到页面', '页面找不到', "Not Found", "访问的页面不存在",
    "page does't exist", 'notice_404', '404 not found', '<title>错误</title>', '内容正在加载', '提示：发生错误', '<title>网站防火墙',
    '无法加载控制器'
]

# ping探测
PING = True

# 设置代理
# SOCKS5 = ('127.0.0.1', 1080)
SOCKS5 = ()

# shodan
SHODAN_API = ''

# VT接口
VIRUSTOTAL_API = ''

# 设置cookie
COOKIE = {'Cookie': 'test'}

```
POC
--------
**1. 根据端口开放或者指纹识别结果来调用POC**  
在script目录下新建python文件，定义好check函数，传进来的参数主要是ip地址、端口列表、指纹识别列表，然后将结果return回去：
```python
import pymongo
from lib.verify import verify

timeout = 2
vuln = ['27017', 'Mongodb']

def check(ip, ports, apps):
    # verify用来验证扫描列表中是否有Mongodb相关的结果，如果端口没有开启则不进行扫描
    if verify(vuln, ports, apps):
        try:
            conn = pymongo.MongoClient(host=ip, port=27017, serverSelectionTimeoutMS=timeout)
            database_list = conn.list_database_names()
            if not database_list:
                conn.close()
                return
            conn.close()
            return '27017 MongoDB Unauthorized Access'
        except Exception as e:
            pass
```
**2. 在目标IP开放的每个HTTP端口上遍历一遍**   
根据传递过来的端口服务列表生成要扫描的url，然后在每个web端口中去访问一遍，下面脚本会获取ip每个http端口的标题  
```python
from lib.verify import get_list
from lib.random_header import HEADERS
from lxml import etree
import requests

def get_title(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=3, verify=False)
        html = etree.HTML(r.text)
        title = html.xpath('//title/text()')
        return url + ' | ' + title[0]
    except:
        pass


def check(ip, ports, apps):
    result = []
    probe = get_list(ip, ports)
    for i in probe:
        out = get_title(i)
        if out:
            result.append(out)
    return result
```

Fingerprint
--------
如何添加指纹识别特征  
修改data/apps.txt文件内容    
**1. 匹配HTTP Header头**  
Cacti|headers|Set-Cookie|Cacti=  
**2. 匹配HTTP响应体**  
ASP|index|index|<a[^>]*?href=('|")[^http][^>]*?\.asp(\?|\#|\1)  
**3. 拆分Headers头，在k或者v中匹配**  
ThinkSNS|match|match|T3_lang  

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
![image](https://github.com/al0ne/Vxscan/raw/master/doc/logo.jpg)
![image](https://github.com/al0ne/Vxscan/raw/master/doc/logo1.jpg)
![image](https://github.com/al0ne/Vxscan/raw/master/doc/logo2.jpg)

Note
------
指纹识别主要调用Wappalyzer与WebEye：  
https://github.com/b4ubles/python3-Wappalyzer  
https://github.com/zerokeeper/WebEye  
Poc参考了:  
BBscan扫描器 https://github.com/lijiejie/BBScan  
POC-T https://github.com/Xyntax/POC-T/tree/2.0/script  
Perun https://github.com/WyAtu/Perun   
参考了anthx的端口扫描、服务判断：
https://raw.githubusercontent.com/AnthraX1/InsightScan/master/scanner.py  
js敏感信息正则提取参考了：  
https://github.com/nsonaniya2010/SubDomainizer  
WAF判断使用的是waf00f与whatwaf的判断规则：  
https://github.com/EnableSecurity/wafw00f  
https://github.com/Ekultek/WhatWaf  
html报告使用了：  
https://github.com/WyAtu/Perun
https://github.com/ly1102   

**请使用者遵守《中华人民共和国网络安全法》，勿用于非授权测试，如作他用所承受的法律责任一概与作者无关，下载使用即代表使用者同意上述观点**。
