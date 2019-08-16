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
from lib.Requests import Requests

vuln = ['solr']


def check(url, ip, ports, apps):
    req = Requests()
    if verify(vuln, ports, apps):
        try:
            url = url + '/solr/'
            r = req.get(url)
            if r.status_code is 200 and 'Solr Admin' in r.content and 'Dashboard' in r.content:
                return 'Apache Solr Admin leask'
        except Exception:
            pass
