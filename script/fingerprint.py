# coding=utf-8
# author: al0ne
# https://github.com/al0ne

from lib.verify import get_list
from lib.Requests import Requests
from plugins.PassiveReconnaissance.wappalyzer import WebPage
import chardet
import re

req = Requests()


def get_title(url):
    try:
        r = req.get(url)
        coding = chardet.detect(r.content).get('encoding')
        text = r.content[:10000].decode(coding)
        webinfo = WebPage(r.url, text, r.headers).info()
        if webinfo.get('apps'):
            return 'URL: ' + url + ' | Fingerprint: ' + ' , '.join(webinfo.get('apps'))
    except:
        pass


def check(url, ip, ports, apps):
    result = []
    probe = get_list(url, ports)
    for i in probe:
        if re.search(r':\d+', i):
            out = get_title(i)
            if out:
                result.append(out)
    if result:
        return result
