# coding=utf-8
import chardet
from lib.iscdn import iscdn
from plugins.ActiveReconnaissance.osdetect import osdetect
from lib.sqldb import Sqldb
from plugins.PassiveReconnaissance.virustotal import virustotal
from plugins.PassiveReconnaissance.reverse_domain import reverse_domain
from lib.url import parse_host, parse_ip
from plugins.InformationGathering.geoip import geoip
from lib.Requests import Requests
from lib.cli_output import console
from plugins.PassiveReconnaissance.wappalyzer import WebPage
from plugins.ActiveReconnaissance.check_waf import checkwaf


def web_save(webinfo):
    Sqldb('result').get_webinfo(webinfo)


def web_info(url):
    host = parse_host(url)
    ipaddr = parse_ip(host)
    url = url.strip('/')
    address = geoip(ipaddr)
    wafresult = checkwaf(url)
    req = Requests()
    try:
        r = req.get(url)
        coding = chardet.detect(r.content).get('encoding')
        r.encoding = coding
        webinfo = WebPage(r.url, r.text, r.headers).info()
    except Exception as e:
        webinfo = {}
    if webinfo:
        console('Webinfo', host, 'Title: {}\n'.format(webinfo.get('title')))
        console('Webinfo', host, 'Fingerprint: {}\n'.format(webinfo.get('apps')))
        console('Webinfo', host, 'Server: {}\n'.format(webinfo.get('server')))
        console('Webinfo', host, 'WAF: {}\n'.format(wafresult))
    else:
        webinfo = {}
        wafresult = 'None'
    if iscdn(host):
        osname = osdetect(host)
    else:
        osname = None
    pdns = virustotal(host)
    reverseip = reverse_domain(host)
    webinfo.update({"pdns": pdns})
    webinfo.update({"reverseip": reverseip})
    data = {
        host: {
            'WAF': wafresult,
            'Ipaddr': ipaddr,
            'Address': address,
            'Webinfo': webinfo,
            'OS': osname,
        }
    }
    return data, webinfo.get('apps')


if __name__ == "__main__":
    web_info('http://127.0.0.1')
