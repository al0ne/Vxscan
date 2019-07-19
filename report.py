# coding = utf-8

import json
import re
import time
import sys
from lib.sqldb import Sqldb

dbname = 'result'


def gen_webinfo():
    tableData = []
    sql = 'select time,domain,waf,title,apps,server,security,address,ipaddr,os,pdns,reverseip from webinfo'
    try:
        res = Sqldb(dbname).query(sql)
        for i in res:
            time, domain, waf, title, apps, server, security, address, ipaddr, os, pdns, reverseip = i
            webinfo = {"time": time, "domain": domain, "waf": waf, "title": title,
                       "apps": apps, "server": server, "security": security,
                       "address": address, "ipaddr": ipaddr, "os": os, "pdns": pdns, "reverseip": reverseip}
            tableData.append(webinfo)
        column = [{"field": "time", "title": "TIME", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "domain", "title": "domain", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "waf", "title": "waf", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "title", "title": "title", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "apps", "title": "apps", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "server", "title": "server", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "security", "title": "security", "width": 100, "tilteAlign": "center",
                   "columnAlign": "center"},
                  {"field": "address", "title": "address", "width": 100, "tilteAlign": "center",
                   "columnAlign": "center"},
                  {"field": "ipaddr", "title": "ipaddr", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "os", "title": "os", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "pdns", "title": "pdns", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "reverseip", "title": "reverseip", "width": 100, "tilteAlign": "center",
                   "columnAlign": "center"}, ]
        data = {
            "name": "webinfo",
            "tableData": tableData,
            "columns": column
        }
        
        return data
    except Exception as e:
        print(e)


def gen_ports():
    tableData = []
    sql = 'select time,ipaddr,service,port from ports'
    try:
        res = Sqldb(dbname).query(sql)
        for i in res:
            time, ipaddr, service, port = i
            ports = {"time": time, "ip": ipaddr, "port": port, "service": service}
            tableData.append(ports)
        column = [{"field": "time", "title": "TIME", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "ip", "title": "IP", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "port", "title": "PORT", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "service", "title": "SERVICE", "width": 100, "tilteAlign": "center",
                   "columnAlign": "center"}, ]
        data = {
            "name": "Ports",
            "tableData": tableData,
            "columns": column
        }
        
        return data
    except Exception as e:
        print(e)


def gen_urls():
    tableData = []
    sql = 'select time,domain,title,url,contype,rsp_len,rsp_code from urls'
    try:
        res = Sqldb(dbname).query(sql)
        for i in res:
            time, domain, title, url, contype, rsp_len, rsp_code = i
            urls = {"time": time, "domain": domain, "title": title, "url": url, "contype": contype, "rsp_len": rsp_len,
                    "rsp_code": rsp_code}
            tableData.append(urls)
        column = [{"field": "time", "title": "TIME", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "domain", "title": "domain", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "title", "title": "title", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "url", "title": "url", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "contype", "title": "contype", "width": 100, "tilteAlign": "center",
                   "columnAlign": "center"},
                  {"field": "rsp_len", "title": "rsp_len", "width": 100, "tilteAlign": "center",
                   "columnAlign": "center"},
                  {"field": "rsp_code", "title": "rsp_code", "width": 100, "tilteAlign": "center",
                   "columnAlign": "center"}]
        data = {
            "name": "URLS",
            "tableData": tableData,
            "columns": column
        }
        return data
    except Exception as e:
        print(e)


def gen_vuln():
    tableData = []
    sql = 'select time, domain, vuln from vuln'
    try:
        res = Sqldb(dbname).query(sql)
        for i in res:
            time, ip, vuln = i
            vuln = {"time": time, "ip": ip, "vuln": vuln}
            tableData.append(vuln)
        column = [{"field": "time", "title": "TIME", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "ip", "title": "IP", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "vuln", "title": "VULN", "width": 100, "tilteAlign": "center", "columnAlign": "center"}, ]
        data = {
            "name": "Vuln",
            "tableData": tableData,
            "columns": column
        }
        return data
    except Exception as e:
        return None


def gener():
    out = []
    for i in [gen_webinfo(), gen_urls(), gen_ports(), gen_vuln()]:
        if i:
            out.append(i)
    result = {"table": out}
    result = json.dumps(result)
    result = re.sub(r'^{|}$', '', result)
    times = time.strftime("%Y%m%d%H%M%S", time.localtime())
    name = 'Vxscan_' + times + '.html'
    with open('report/report.htm', 'r', encoding='utf-8') as f, open(name, 'w') as f1:
        text = f.read()
        f1.write(text.replace("'summary': {}", result))


if __name__ == "__main__":
    if sys.argv[1]:
        dbname = sys.argv[1]
        dbname = re.sub('.db', '', dbname)
    gener()
