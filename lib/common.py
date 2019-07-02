# author: al0ne
# https://github.com/al0ne

from lib.waf import WAF_RULE
import re
import requests
import sys
import geoip2.database
import socket
import traceback
import json
import tldextract
from virustotal_python import Virustotal
from lib.osdetect import osdetect
from urllib import parse
from lib.wappalyzer import WebPage
from lib.random_header import get_ua
from lib.scan_port import ScanPort
from lib.vuln import Vuln
from lib.jsparse import JsParse
from lib.sql_injection import sql_check
from lib.iscdn import iscdn
from lib.settings import TIMEOUT, virustotal_api, POC

payload = " AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(XSS)</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')"


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
        pass
    return 'None'


def reverse_domain(host):
    # 查询旁站
    if iscdn(host):
        result = []
        data = {"remoteAddress": "{0}".format(host), "key": ""}
        header = get_ua()
        header.update({'Referer': 'https://www.yougetsignal.com/tools/web-sites-on-web-server/'})
        header.update({'origin': 'https://www.yougetsignal.com'})
        try:
            r = requests.post('https://domains.yougetsignal.com/domains.php', headers=header, data=data, timeout=5,
                              verify=False)
            text = json.loads(r.text)
            domain = tldextract.extract(host)
            for i in text.get('domainArray'):
                url = i[0]
                if url != host:
                    if tldextract.extract(url).domain == domain.domain:
                        result.append(url)
                    elif re.search(r'\d+\.\d+\.\d+\.\d+', url):
                        result.append(url)
        except:
            try:
                r = requests.get('http://api.hackertarget.com/reverseiplookup/?q={}'.format(host), headers=get_ua(),
                                 timeout=4, verify=False)
                if '<html>' not in r.text:
                    text = r.text
                    for _ in text.split('\n'):
                        if _:
                            result.append(_)
                else:
                    result = []
            except:
                pass
        return result


def virustotal(host):
    # VT接口，主要用来查询PDNS，绕过CDN
    if virustotal_api:
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
        r = requests.get(url, headers=get_ua(), timeout=TIMEOUT, verify=False)
    except Exception as e:
        pass
    sql = ''
    if 'r' in locals().keys():
        try:
            webinfo = (WebPage(r.url, r.content.decode('utf8'), r.headers).info())
            result = checkwaf(r.headers, r.text[:10000])
            if result == 'NoWAF':
                r = requests.get(
                    url + '/index.php?id=1 ' + payload, headers=get_ua(), timeout=TIMEOUT, verify=False)
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
    if iscdn(host):
        open_port = ScanPort(url).pool()
    else:
        open_port = ['CDN:0']
    sys.stdout.write(bcolors.RED + "PortScan：\n" + bcolors.ENDC)
    for _ in open_port:
        sys.stdout.write(bcolors.OKGREEN + '[+] {}\n'.format(_) + bcolors.ENDC)
    if POC:
        vuln = Vuln(url, open_port, webinfo.get('apps')).run()
    else:
        vuln = []
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
    if not address:
        address = 'None'
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
