# coding = utf-8

import json
import re
import time
import sys
import logging
from lib.sqldb import Sqldb

dbname = 'result'


def get_port(ipaddr):
    try:
        sql = "select port from ports where ipaddr='{}'".format(ipaddr)
        getport = Sqldb(dbname).query(sql)
        if getport:
            result = []
            for i in getport:
                result.append(i[0])
            result = list(map(int, result))
            result = sorted(result)
            result = list(map(str, result))
            ports = ' , '.join(result)
            return ports
    except Exception as e:
        logging.exception(e)


def gen_webinfo():
    tableData = []
    sql = 'select time,domain,waf,title,apps,server,address,ipaddr,os,pdns,reverseip from webinfo'
    try:
        res = Sqldb(dbname).query(sql)
        for i in res:
            time, domain, waf, title, apps, server, address, ipaddr, os, pdns, reverseip = i
            ports = get_port(domain)
            webinfo = {"time": time, "domain": domain, "waf": waf, "title": title,
                       "apps": apps, "server": server, "address": address, "ipaddr": ipaddr, "ports": ports, "os": os,
                       "reverseip": reverseip}
            tableData.append(webinfo)
        column = [{"field": "time", "title": "TIME", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "domain", "title": "domain", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "waf", "title": "waf", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "title", "title": "title", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "apps", "title": "apps", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "server", "title": "server", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "address", "title": "address", "width": 100, "tilteAlign": "center",
                   "columnAlign": "center"},
                  {"field": "ipaddr", "title": "ipaddr", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "ports", "title": "ports", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "os", "title": "os", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  # {"field": "pdns", "title": "pdns", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "reverseip", "title": "reverseip", "width": 100, "tilteAlign": "center",
                   "columnAlign": "center"}, ]
        data = {
            "name": "webinfo",
            "tableData": tableData,
            "columns": column
        }
        
        return data
    except TypeError:
        pass
    except Exception as e:
        logging.exception(e)


def gen_ports():
    tableData = []
    sql = 'select time,ipaddr,service,port,banner from ports'
    try:
        res = Sqldb(dbname).query(sql)
        for i in res:
            time, ipaddr, service, port, banner = i
            ports = {"time": time, "ip": ipaddr, "port": port, "service": service, "banner": banner}
            tableData.append(ports)
        column = [{"field": "time", "title": "TIME", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "ip", "title": "IP", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "port", "title": "PORT", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "service", "title": "SERVICE", "width": 100, "tilteAlign": "center",
                   "columnAlign": "center"},
                  {"field": "banner", "title": "Banner", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  ]
        data = {
            "name": "Ports",
            "tableData": tableData,
            "columns": column
        }
        
        return data
    except TypeError:
        pass
    except Exception as e:
        logging.exception(e)


def gen_urls():
    tableData = []
    sql = 'select time,domain,title,url,contype,rsp_len,rsp_code from urls'
    try:
        res = Sqldb(dbname).query(sql)
        if res:
            for i in res:
                time, domain, title, url, contype, rsp_len, rsp_code = i
                urls = {"time": time, "domain": domain, "title": title, "url": url, "contype": contype,
                        "rsp_len": rsp_len,
                        "rsp_code": rsp_code}
                tableData.append(urls)
            column = [{"field": "time", "title": "TIME", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                      {"field": "domain", "title": "Domain", "width": 100, "tilteAlign": "center",
                       "columnAlign": "center"},
                      {"field": "title", "title": "TITLE", "width": 100, "tilteAlign": "center",
                       "columnAlign": "center"},
                      {"field": "url", "title": "URL", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                      {"field": "contype", "title": "ConType", "width": 100, "tilteAlign": "center",
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
    except TypeError:
        pass
    except Exception as e:
        logging.exception(e)


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
    except TypeError:
        pass
    except Exception as e:
        logging.exception(e)


def gen_crawl():
    tableData = []
    sql = 'select time, domain, type,leaks from crawl'
    try:
        res = Sqldb(dbname).query(sql)
        for i in res:
            time, domain, type, leaks = i
            vuln = {"time": time, "domain": domain, "type": type, "leaks": leaks}
            tableData.append(vuln)
        column = [{"field": "time", "title": "TIME", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "domain", "title": "DOMAIN", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "type", "title": "TYPE", "width": 100, "tilteAlign": "center", "columnAlign": "center"},
                  {"field": "leaks", "title": "Leaks", "width": 100, "tilteAlign": "center", "columnAlign": "center"}, ]
        data = {
            "name": "Crawl",
            "tableData": tableData,
            "columns": column
        }
        return data
    except TypeError:
        pass
    except Exception as e:
        logging.exception(e)


def gener():
    out = []
    for i in [gen_webinfo(), gen_urls(), gen_ports(), gen_vuln(), gen_crawl()]:
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
    # if sys.argv[1]:
    #     dbname = sys.argv[1]
    #     dbname = re.sub('.db', '', dbname)
    gener()
