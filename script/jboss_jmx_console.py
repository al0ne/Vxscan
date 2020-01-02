# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import re

from lib.Requests import Requests
from lib.verify import get_list

req = Requests()


def get_title(url):
    try:
        payload = '/jmx-console/'
        r = req.get(url + payload)
        if "jboss" in r.text:
            return 'Jboss console/ page: ' + url + payload
    except Exception:
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
