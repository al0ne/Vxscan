# coding=utf-8
import logging

import chardet

from lib.Requests import Requests
from lib.cli_output import console
from lib.iscdn import iscdn
from lib.url import parse_host, parse_ip
from plugins.ActiveReconnaissance.check_waf import checkwaf
from plugins.ActiveReconnaissance.osdetect import osdetect
from plugins.InformationGathering.geoip import geoip
from plugins.PassiveReconnaissance.wappalyzer import WebPage


def web_info(url):
    host = parse_host(url)
    ipaddr = parse_ip(host)
    url = url.strip('/')
    address = geoip(ipaddr)
    wafresult = checkwaf(url)
    req = Requests()
    # noinspection PyBroadException
    try:
        r = req.get(url)
        coding = chardet.detect(r.content).get('encoding')
        r.encoding = coding
        webinfo = WebPage(r.url, r.text, r.headers).info()
    except Exception as e:
        logging.exception(e)
        webinfo = {}
    if webinfo:
        console('Webinfo', host, 'title: {}\n'.format(webinfo.get('title')))
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
    
    data = {
        host: {
            'WAF': wafresult,
            'Ipaddr': ipaddr,
            'Address': address,
            'Webinfo': webinfo,
            'OS': osname,
        }
    }
    
    return data, webinfo.get('apps'), webinfo.get('title')


if __name__ == "__main__":
    web_info('http://127.0.0.1')
