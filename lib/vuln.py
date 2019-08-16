# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import glob
import importlib
import time
import os
import concurrent.futures
import logging
from lib.cli_output import console
from lib.sqldb import Sqldb
from lib.url import parse_host
from plugins.BruteForce.crack import Crack


class Vuln():
    def __init__(self, url, host, ports, apps):
        host = parse_host(host)
        self.url = url
        self.ip = host
        self.apps = apps
        self.ports = ports
        self.out = []
    
    def vuln(self, script):
        check_func = getattr(script, 'check')
        result = check_func(self.url, self.ip, self.ports, self.apps)
        if result:
            if type(result) == str:
                self.out.append(result)
            else:
                self.out.extend(result)
    
    def run(self):
        scripts = []
        try:
            for _ in glob.glob('script/*.py'):
                script_name = os.path.basename(_).replace('.py', '')
                vuln = importlib.import_module('script.%s' % script_name)
                scripts.append(vuln)
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=20) as executor:
                executor.map(self.vuln, scripts)
            self.out = list(filter(None, self.out))
            for i in self.out:
                console('Vuln', self.ip, i + '\n')
            brute_result = Crack().pool(self.ip, self.ports)
            if brute_result:
                self.out.extend(brute_result)
            Sqldb('result').get_vuln(self.ip, self.out)
        except Exception as e:
            logging.exception(e)


if __name__ == "__main__":
    start_time = time.time()
    Vuln('http://127.0.0.1', '127.0.0.1', ['http:80', 'https:8000'], ["iis", "Apache", "jQuery"]).run()
    end_time = time.time()
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
