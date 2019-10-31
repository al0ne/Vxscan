# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import re
from lib.Requests import Requests
from lib.verify import get_list
from lib.settings import PAGE_404

path = [
    '/.git/config', '/.svn/entries', '/.git/index', '/.git/HEAD', '/.ssh/known_hosts', '/.DS_Store', '/.hg',
    '/WEB-INF/web.xml', '/WEB-INF/database.properties', '/CVS/Entries', '/_cat/'
]


def verify(text):
    result = True
    for i in PAGE_404:
        if i in text:
            result = False
            break
    return result


def get_info(url):
    try:
        req = Requests()
        for i in path:
            r = req.get(url + i)
            if r.status_code == 200 and '<html' not in r.text:
                if not re.search(r'{"\w+":|<head>|<form\s|<div\s|<input\s|<html|</a>|Active connections', r.text):
                    if verify(r.text):
                        return 'leaks : ' + url + i
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
