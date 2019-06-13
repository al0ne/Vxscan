# author: al0ne
# https://github.com/al0ne

from lib.verify import get_list
from lib.random_header import HEADERS
from lxml import etree
import requests


def get_title(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=3, verify=False)
        r.encoding = "utf-8"
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
    if result:
        return result
