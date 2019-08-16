# author: al0ne
# https://github.com/al0ne

from lib.verify import get_list
from lxml import etree
from lib.Requests import Requests
import chardet
import re

req = Requests()


def get_title(url):
    try:
        r = req.get(url)
        if r.status_code == 200:
            coding = chardet.detect(r.content).get('encoding')
            text = r.content[:10000].decode(coding)
            html = etree.HTML(text)
            title = html.xpath('//title/text()')
            return url + ' | ' + title[0]
    except:
        pass


def check(url, ip, ports, apps):
    result = []
    probe = get_list(ip, ports)
    for i in probe:
        if re.search(r':\d+', i):
            out = get_title(i)
            if out:
                result.append(out)
    if result:
        return result
