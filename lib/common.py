# author: al0ne
# https://github.com/al0ne

import sys
import chardet
from lib.bcolors import bcolors
from lib.iscdn import iscdn
from lib.url import parse_host, parse_ip
from lib.Requests import Requests
from lib.sqldb import Sqldb
from lib.vuln import Vuln
from lib.settings import SCANDIR
from plugins.Scanning.dir_scan import DirScan
from plugins.ActiveReconnaissance.osdetect import osdetect
from plugins.ActiveReconnaissance.check_waf import checkwaf
from plugins.PassiveReconnaissance.wappalyzer import WebPage
from plugins.PassiveReconnaissance.virustotal import virustotal
from plugins.PassiveReconnaissance.reverse_domain import reverse_domain
from plugins.InformationGathering.geoip import geoip
from plugins.Scanning.port_scan import ScanPort


def web_save(webinfo):
    Sqldb('result').get_webinfo(webinfo)


def start(url):
    host = parse_host(url)
    ipaddr = parse_ip(host)
    url = url.strip('/')
    sys.stdout.write(bcolors.RED + '-' * 100 + '\n' + bcolors.ENDC)
    sys.stdout.write(bcolors.RED + 'Host: ' + host + '\n' + bcolors.ENDC)
    sys.stdout.write(bcolors.RED + '-' * 100 + '\n' + bcolors.ENDC)
    address = geoip(ipaddr)
    try:
        # 判断主域名是否开放
        req = Requests()
        r = req.get(url)
    except Exception as e:
        pass
    if 'r' in locals().keys():
        wafresult = checkwaf(host)
        try:
            coding = chardet.detect(r.content).get('encoding')
            r.encoding = coding
            webinfo = (WebPage(r.url, r.text, r.headers).info())
        except Exception as e:
            webinfo = {}
        if webinfo:
            sys.stdout.write(bcolors.RED + "Webinfo：\n" + bcolors.ENDC)
            sys.stdout.write(bcolors.OKGREEN + '[+] Title: {}\n'.format(webinfo.get('title')) + bcolors.ENDC)
            sys.stdout.write(bcolors.OKGREEN + '[+] Fingerprint: {}\n'.format(webinfo.get('apps')) + bcolors.ENDC)
            sys.stdout.write(bcolors.OKGREEN + '[+] Server: {}\n'.format(webinfo.get('server')) + bcolors.ENDC)
            sys.stdout.write(bcolors.OKGREEN + '[+] WAF: {}\n'.format(wafresult) + bcolors.ENDC)
    else:
        webinfo = {}
        wafresult = 'None'
    pdns = virustotal(host)
    reverseip = reverse_domain(host)
    webinfo.update({"pdns": pdns})
    webinfo.update({"reverseip": reverseip})
    if iscdn(host):
        open_port = ScanPort(url).pool()
    else:
        open_port = ['CDN:0']
    osname = osdetect(host)
    data = {
        host: {
            'WAF': wafresult,
            'Ipaddr': ipaddr,
            'Address': address,
            'Webinfo': webinfo,
            'OS': osname,
        }
    }
    web_save(data)
    Vuln(host, open_port, webinfo.get('apps')).run()
    if 'r' in locals().keys() and not SCANDIR:
        dirscan = DirScan('result')
        dirscan.pool(url)


if __name__ == "__main__":
    start('http://127.0.0.1')
