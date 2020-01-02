# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import re

from lib.Requests import Requests
from lib.settings import PAGE_404
from lib.verify import get_list

path = [
    '/admin', '/login', '/manage', '/manager', '/System', '/User', '/adminlogin', '/Admin_login', '/backage',
    '/login.php', '/admin.php', '/admin_login.php', '/main/login'
]


def verify(text):
    result = True
    for i in PAGE_404:
        if i in text:
            result = False
            break
    if re.search('^false$|^post2$|宝塔Linux面板', text):
        result = False
    return result


def get_info(url):
    try:
        req = Requests()
        for i in path:
            r = req.get(url + i)
            if r.status_code == 200:
                if re.search(r'admin|login|manager|登陆|管理|后台|type="password"|入口|admin_passwd', r.text, re.S):
                    if verify(r.text):
                        return 'Admin_Page : ' + url + i
            elif r.status_code == 403:
                return 'May be the login page : ' + url + i

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
