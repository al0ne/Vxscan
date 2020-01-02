# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import re

from lib.Requests import Requests
from lib.verify import get_list

path = ['/1.php', '/p.php', '/phpinfo.php', '/info.php', '/i.php', '/test.php', '/a.php', '/?phpinfo=1', '/111.php']


def get_info(url):
    try:
        req = Requests()
        for i in path:
            r = req.get(url + i)
            if r.status_code == 200:
                if '<title>phpinfo()' in r.text or 'php_version' in r.text:
                    return 'phpinfo leaks: ' + url + i
    except:
        pass


def check(url, ip, ports, apps):
    result = []
    probe = get_list(url, ports)
    for i in probe:
        if re.search(r':\d+', i):
            out = get_info(i)
            if out:
                result.append(out)
    if result:
        return result
