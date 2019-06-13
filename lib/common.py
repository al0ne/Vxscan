# author: al0ne
# https://github.com/al0ne

from lib.waf import WAF_RULE
import re
import requests
import sys
import geoip2.database
import socket
import traceback
import ipaddress
import json
import tldextract
from virustotal_python import Virustotal
from lib.osdetect import osdetect
from urllib import parse
from lib.wappalyzer import WebPage
from lib.random_header import HEADERS
from lib.scan_port import ScanPort
from lib.vuln import Vuln
from lib.jsparse import JsParse
from lib.sql_injection import sql_check
from lib.settings import TIMEOUT, virustotal_api

payload = " AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(XSS)</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')"

# 通过VT查询pdns，然后排除国内外常见的cdn段，如果出现极有可能是真实ip
cdns = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
        '108.162.192.0/18',
        '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15',
        '104.16.0.0/12',
        '172.64.0.0/13', '131.0.72.0/22', '13.124.199.0/24', '144.220.0.0/16', '34.226.14.0/24', '52.124.128.0/17',
        '54.230.0.0/16', '54.239.128.0/18', '52.82.128.0/19', '99.84.0.0/16', '52.15.127.128/26', '35.158.136.0/24',
        '52.57.254.0/24', '18.216.170.128/25', '13.54.63.128/26', '13.59.250.0/26', '13.210.67.128/26',
        '35.167.191.128/26', '52.47.139.0/24', '52.199.127.192/26', '52.212.248.0/26', '205.251.192.0/19',
        '52.66.194.128/26', '54.239.192.0/19', '70.132.0.0/18', '13.32.0.0/15', '13.224.0.0/14', '13.113.203.0/24',
        '34.195.252.0/24', '35.162.63.192/26', '34.223.12.224/27', '13.35.0.0/16', '204.246.172.0/23',
        '204.246.164.0/22', '52.56.127.0/25', '204.246.168.0/22', '13.228.69.0/24', '34.216.51.0/25',
        '71.152.0.0/17', '216.137.32.0/19', '205.251.249.0/24', '99.86.0.0/16', '52.46.0.0/18', '52.84.0.0/15',
        '54.233.255.128/26', '130.176.0.0/16', '64.252.64.0/18', '52.52.191.128/26', '204.246.174.0/23',
        '64.252.128.0/18', '205.251.254.0/24', '143.204.0.0/16', '205.251.252.0/23', '52.78.247.128/26',
        '204.246.176.0/20', '52.220.191.0/26', '13.249.0.0/16', '54.240.128.0/18', '205.251.250.0/23',
        '52.222.128.0/17', '54.182.0.0/16', '54.192.0.0/16', '34.232.163.208/29', '58.250.143.0/24',
        '58.251.121.0/24', '59.36.120.0/24', '61.151.163.0/24', '101.227.163.0/24', '111.161.109.0/24',
        '116.128.128.0/24', '123.151.76.0/24', '125.39.46.0/24', '140.207.120.0/24', '180.163.22.0/24',
        '183.3.254.0/24', '223.166.151.0/24', '113.107.238.0/24', '106.42.25.0/24', '183.222.96.0/24',
        '117.21.219.0/24', '116.55.250.0/24', '111.202.98.0/24', '111.13.147.0/24', '122.228.238.0/24',
        '58.58.81.0/24', '1.31.128.0/24', '123.155.158.0/24', '106.119.182.0/24', '180.97.158.0/24',
        '113.207.76.0/24', '117.23.61.0/24', '118.212.233.0/24', '111.47.226.0/24', '219.153.73.0/24',
        '113.200.91.0/24', '1.32.240.0/24', '203.90.247.0/24', '183.110.242.0/24', '202.162.109.0/24',
        '182.23.211.0/24', '1.32.242.0/24', '1.32.241.0/24', '202.162.108.0/24', '185.254.242.0/24',
        '109.94.168.0/24', '109.94.169.0/24', '1.32.243.0/24', '61.120.154.0/24', '1.255.41.0/24',
        '112.90.216.0/24', '61.213.176.0/24', '1.32.238.0/24', '1.32.239.0/24', '1.32.244.0/24', '111.32.135.0/24',
        '111.32.136.0/24', '125.39.174.0/24', '125.39.239.0/24', '112.65.73.0/24', '112.65.74.0/24',
        '112.65.75.0/24', '119.84.92.0/24', '119.84.93.0/24', '113.207.100.0/24', '113.207.101.0/24',
        '113.207.102.0/24', '180.163.188.0/24', '180.163.189.0/24', '163.53.89.0/24', '101.227.206.0/24',
        '101.227.207.0/24', '119.188.97.0/24', '119.188.9.0/24', '61.155.149.0/24', '61.156.149.0/24',
        '61.155.165.0/24', '61.182.137.0/24', '61.182.136.0/24', '120.52.29.0/24', '120.52.113.0/24',
        '222.216.190.0/24', '219.159.84.0/24', '183.60.235.0/24', '116.31.126.0/24', '116.31.127.0/24',
        '117.34.13.0/24', '117.34.14.0/24', '42.236.93.0/24', '42.236.94.0/24', '119.167.246.0/24',
        '150.138.149.0/24', '150.138.150.0/24', '150.138.151.0/24', '117.27.149.0/24', '59.51.81.0/24',
        '220.170.185.0/24', '220.170.186.0/24', '183.61.236.0/24', '14.17.71.0/24', '119.147.134.0/24',
        '124.95.168.0/24', '124.95.188.0/24', '61.54.46.0/24', '61.54.47.0/24', '101.71.55.0/24', '101.71.56.0/24',
        '183.232.51.0/24', '183.232.53.0/24', '157.255.25.0/24', '157.255.26.0/24', '112.25.90.0/24',
        '112.25.91.0/24', '58.211.2.0/24', '58.211.137.0/24', '122.190.2.0/24', '122.190.3.0/24', '183.61.177.0/24',
        '183.61.190.0/24', '117.148.160.0/24', '117.148.161.0/24', '115.231.186.0/24', '115.231.187.0/24',
        '113.31.27.0/24', '222.186.19.0/24', '122.226.182.0/24', '36.99.18.0/24', '123.133.84.0/24',
        '221.204.202.0/24', '42.236.6.0/24', '61.130.28.0/24', '61.174.9.0/24', '223.94.66.0/24', '222.88.94.0/24',
        '61.163.30.0/24', '223.94.95.0/24', '223.112.227.0/24', '183.250.179.0/24', '120.241.102.0/24',
        '125.39.5.0/24', '124.193.166.0/24', '122.70.134.0/24', '111.6.191.0/24', '122.228.198.0/24',
        '121.12.98.0/24', '60.12.166.0/24', '118.180.50.0/24', '183.203.7.0/24', '61.133.127.0/24',
        '113.7.183.0/24', '210.22.63.0/24', '60.221.236.0/24', '122.227.237.0/24', '123.6.13.0/24',
        '202.102.85.0/24', '61.160.224.0/24', '182.140.227.0/24', '221.204.14.0/24', '222.73.144.0/24',
        '61.240.144.0/24', '36.27.212.0/24', '125.88.189.0/24', '120.52.18.0/24', '119.84.15.0/24',
        '180.163.224.0/24']


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RED = '\033[31m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def checkwaf(headers, content):
    for i in WAF_RULE:
        name, method, position, regex = i.split('|')
        if method == 'headers':
            if headers.get(position) != None:
                if re.search(regex, str(headers.get(position))) != None:
                    return name
        else:
            if re.search(regex, str(content)):
                return name
    return 'NoWAF'


def geoip(ip):
    # 获取IP地理位置
    geoip2.database
    reader = geoip2.database.Reader('db/GeoLite2-City.mmdb')
    try:
        response = reader.city(ip)
        country = response.country.names["zh-CN"]
        site = response.subdivisions.most_specific.names.get("zh-CN")
        if not site:
            site = ''
        city = response.city.names.get("zh-CN")
        if not city:
            city = ''
        return '{} {} {}'.format(country, site, city)
    except:
        return 'None'


def iscdn(host):
    if not re.search(r'\d+\.\d+\.\d+\.\d+', host):
        socket.setdefaulttimeout(1)
        host = socket.gethostbyname(host)
    result = True
    for cdn in cdns:
        if (ipaddress.ip_address(host) in ipaddress.ip_network(cdn)):
            result = False
    return result


def reverse_domain(host):
    # 查询旁站
    if iscdn(host):
        result = []
        data = {"remoteAddress": "{0}".format(host), "key": ""}
        header = HEADERS
        header.update({'Referer': 'https://www.yougetsignal.com/tools/web-sites-on-web-server/'})
        header.update({'origin': 'https://www.yougetsignal.com'})
        try:
            r = requests.post('https://domains.yougetsignal.com/domains.php', headers=header, data=data, timeout=5)
            text = json.loads(r.text)
            domain = tldextract.extract(host)
            for i in text.get('domainArray'):
                url = i[0]
                if url != host:
                    if tldextract.extract(url).domain == domain.domain:
                        result.append(url)
                    elif re.search(r'\d+\.\d+\.\d+\.\d+', url):
                        result.append(url)
        except (TypeError, json.decoder.JSONDecodeError):
            r = requests.get('http://api.hackertarget.com/reverseiplookup/?q={}'.format(host), headers=HEADERS,
                             timeout=5)
            if '<html>' not in r.text:
                text = r.text
                for _ in text.split('\n'):
                    if _:
                        result.append(_)
            else:
                result = []
        return result


def virustotal(host):
    # VT接口，主要用来查询PDNS，绕过CDN
    vtotal = Virustotal(virustotal_api)
    if re.search(r'\d+\.\d+\.\d+\.\d+', host):
        return ['None']
    resp = vtotal.domain_report(host)
    history_ip = []

    if resp.get('status_code') != 403:
        for i in resp.get('json_resp').get('resolutions'):
            address = i.get('ip_address')
            timeout = i.get('last_resolved')
            if iscdn(address):
                history_ip.append(address + ' : ' + timeout)
        return history_ip[-10:]
    else:
        return ['None']


def start(url):
    try:
        result = 'NoWAF'
        if (not parse.urlparse(url).path) and (parse.urlparse(url).path != '/'):
            host = url.replace('http://', '').replace('https://', '').rstrip('/')
        else:
            host = url.replace('http://', '').replace('https://', '').rstrip('/')
            host = re.sub('/\w+', '', host)
        if ':' in host:
            host = re.sub(r':\d+', '', host)
        socket.setdefaulttimeout(1)
        ipaddr = socket.gethostbyname(host)
        address = geoip(ipaddr)
        sys.stdout.write(bcolors.RED + '-' * 100 + '\n' + bcolors.ENDC)
        sys.stdout.write(bcolors.RED + 'Host: ' + host + '\n' + bcolors.ENDC)
        sys.stdout.write(bcolors.RED + '-' * 100 + '\n' + bcolors.ENDC)
        sys.stdout.write(bcolors.RED + "GeoIP：\n" + bcolors.ENDC)
        sys.stdout.write(bcolors.OKGREEN + '[+] Address: {}\n'.format(address) + bcolors.ENDC)
        sys.stdout.write(bcolors.OKGREEN + '[+] Ipaddr: {}\n'.format(ipaddr) + bcolors.ENDC)
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
    except Exception as e:
        pass
    sql = ''
    if 'r' in locals().keys():
        try:
            webinfo = (WebPage(r.url, r.content.decode('utf8'), r.headers).info())
            result = checkwaf(r.headers, r.text[:10000])
            if result == 'NoWAF':
                r = requests.get(
                    url + '/index.php?id=1 ' + payload, headers=HEADERS, timeout=TIMEOUT)
                result = checkwaf(r.headers, r.text[:10000])
        except Exception as e:
            webinfo = {}
            traceback.print_exc()
        if webinfo:
            sys.stdout.write(bcolors.RED + "Webinfo：\n" + bcolors.ENDC)
            sys.stdout.write(bcolors.OKGREEN + '[+] Title: {}\n'.format(webinfo.get('title')) + bcolors.ENDC)
            sys.stdout.write(bcolors.OKGREEN + '[+] Fingerprint: {}\n'.format(webinfo.get('apps')) + bcolors.ENDC)
            sys.stdout.write(bcolors.OKGREEN + '[+] Server: {}\n'.format(webinfo.get('server')) + bcolors.ENDC)
            sys.stdout.write(bcolors.OKGREEN + '[+] WAF: {}\n'.format(result) + bcolors.ENDC)
        pdns = virustotal(host)
        reverseip = reverse_domain(host)
        sys.stdout.write(bcolors.RED + "VT PDNS：\n" + bcolors.ENDC)
        sys.stdout.write(bcolors.OKGREEN + "\n".join("[+] " + str(i) for i in pdns) + "\n" + bcolors.ENDC)
        if reverseip:
            sys.stdout.write(bcolors.RED + "Reverse IP Domain Check：\n" + bcolors.ENDC)
            sys.stdout.write(bcolors.OKGREEN + "\n".join("[+] " + str(i) for i in reverseip) + "\n" + bcolors.ENDC)
        jsparse = JsParse(url).jsparse()
        sql = sql_check(url)
        webinfo.update({"pdns": pdns})
        webinfo.update({"reverseip": reverseip})
    else:
        webinfo = {}
        jsparse = ''
    open_port = ScanPort(url).pool()
    if open_port:
        sys.stdout.write(bcolors.RED + "PortScan：\n" + bcolors.ENDC)
        for _ in open_port:
            sys.stdout.write(bcolors.OKGREEN + '[+] {}\n'.format(_) + bcolors.ENDC)
    vuln = Vuln(url, open_port, webinfo.get('apps')).run()
    if jsparse:
        jsparse = list(map(lambda x: 'Leaks: ' + x, jsparse))
        vuln.extend(jsparse)
    if sql:
        vuln.extend(sql)
    vuln = list(filter(None, vuln))
    if not (len(vuln) == 1 and ('' in vuln)):
        sys.stdout.write(bcolors.RED + "Vuln：\n" + bcolors.ENDC)
        sys.stdout.write(bcolors.OKGREEN + "\n".join("[+] " + str(i) for i in vuln) + "\n" + bcolors.ENDC)
    url = parse.urlparse(url)
    osname = osdetect(url.netloc)
    if not osname:
        osname = 'None'
    sys.stdout.write(bcolors.RED + "OS：\n" + bcolors.ENDC)
    sys.stdout.write(bcolors.OKGREEN + '[+] {}\n'.format(osname) + bcolors.ENDC)
    data = {
        url.netloc: {
            'WAF': result,
            'Ipaddr': ipaddr,
            'Address': address,
            'Webinfo': webinfo,
            'Ports': open_port,
            'OS': osname,
            'Vuln': vuln
        }
    }
    return data, result


if __name__ == "__main__":
    geoip('1.1.1.1')
