# coding=utf-8
# author: al0ne
# https://github.com/al0ne

from lib.verify import get_list
from lxml import etree
from lib.Requests import Requests
import chardet
import re

req = Requests()


def get_title(url):
    code = 0

    try:
        r = req.get(url)
        code = r.status_code
        coding = chardet.detect(r.content).get('encoding')
        text = r.content[:10000].decode(coding)
        html = etree.HTML(text)
        title = html.xpath('//title/text()')
        if title:
            return url + ' | ' + title[0]
        else:
            return url + ' | Status_code: ' + str(code)
    except:
        pass

    return url + ' | Status_code: ' + str(code)


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
