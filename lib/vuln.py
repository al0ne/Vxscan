# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import glob
import importlib
import time
import os
import concurrent.futures
import sys
from lib.bcolors import bcolors
from lib.url import parse_host
from plugins.ActiveReconnaissance.crawl import crawl
from lib.sqldb import Sqldb

class Vuln():
    def __init__(self, host, ports, apps):
        host = parse_host(host)
        self.ip = host
        self.apps = apps
        self.ports = ports
        self.out = []
    
    def vuln(self, script):
        check_func = getattr(script, 'check')
        result = check_func(self.ip, self.ports, self.apps)
        if result:
            if type(result) == str:
                self.out.append(result)
            else:
                self.out.extend(result)
    
    def save(self, result):
        Sqldb('result').get_vuln(self.ip, result)
        
    def run(self):
        scripts = []
        sys.stdout.write(bcolors.RED + "Vuln：\n" + bcolors.ENDC)
        try:
            for _ in glob.glob('script/*.py'):
                script_name = os.path.basename(_).replace('.py', '')
                vuln = importlib.import_module('script.%s' % script_name)
                scripts.append(vuln)
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=20) as executor:
                executor.map(self.vuln, scripts)
        except Exception as e:
            print(e)
        crawl_info = crawl(self.ip).pool()
        
        self.out.extend(crawl_info)
        self.out = list(filter(None, self.out))
        sys.stdout.write(bcolors.OKGREEN + "\n".join("[+] " + str(i) for i in self.out) + "\n" + bcolors.ENDC)
        self.save(self.out)


if __name__ == "__main__":
    start_time = time.time()
    print(Vuln('127.0.0.1', ['http:80'], ["iis", "Apache", "jQuery"]).run())
    end_time = time.time()
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
