# author: al0ne
# https://github.com/al0ne

import re

from lib.iscdn import iscdn
from lib.settings import SCANDIR, CRAWL
from lib.sqldb import Sqldb
from lib.url import parse_ip
from lib.verify import verify_https
from lib.vuln import Vuln
from lib.web_info import web_info
from plugins.ActiveReconnaissance.crawl import Crawl
from plugins.Scanning.async_scan import DirScan
from plugins.Scanning.port_scan import ScanPort


def web_save(webinfo, dbname):
    Sqldb(dbname).get_webinfo(webinfo)


def start(target, dbname='result'):
    if dbname != 'result':
        dbname = re.sub(r'.db', '', dbname)
    title = 'test'
    host = parse_ip(target)
    url = verify_https(target)
    if url:
        isopen = True
    else:
        isopen = False
    if isopen:
        data, apps, title = web_info(url)
    else:
        data = ''
        apps = {}
    if iscdn(host):
        open_port = ScanPort(url, dbname).pool()
    else:
        open_port = ['CDN:0']
    
    # 调用POC
    Vuln(url, host, open_port, apps, dbname).run()
    
    if isopen:
        if CRAWL:
            Crawl(url, dbname).pool()
        if SCANDIR:
            dirscan = DirScan(dbname, apps, url, title)
            dirscan.pool()
    if data:
        web_save(data, dbname)


if __name__ == "__main__":
    start('http://127.0.0.1')
