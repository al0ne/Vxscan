# author: al0ne
# https://github.com/al0ne

from lib.iscdn import iscdn
from lib.url import parse_ip
from lib.web_info import web_info
from lib.sqldb import Sqldb
from lib.vuln import Vuln
from lib.verify import verify_https
from lib.settings import SCANDIR, CRAWL
from plugins.Scanning.dir_scan import DirScan
from plugins.ActiveReconnaissance.crawl import crawl
from plugins.Scanning.port_scan import ScanPort


def web_save(webinfo):
    Sqldb('result').get_webinfo(webinfo)


def start(target):
    host = parse_ip(target)
    url = verify_https(target)
    if url:
        isopen = True
    else:
        isopen = False
    if isopen:
        data, apps = web_info(url)
    else:
        data = ''
        apps = {}
    if iscdn(host):
        open_port = ScanPort(url).pool()
    else:
        open_port = ['CDN:0']
    Vuln(url, host, open_port, apps).run()
    if isopen:
        if CRAWL:
            crawl(url).pool()
        if SCANDIR:
            dirscan = DirScan('result', apps)
            dirscan.pool(url)
    if data:
        web_save(data)


if __name__ == "__main__":
    start('http://127.0.0.1')
