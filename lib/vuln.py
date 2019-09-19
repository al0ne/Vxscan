# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import glob
import importlib
import time
import logging
import os
import random
import concurrent.futures
from lib.cli_output import console
from lib.sqldb import Sqldb
from lib.url import parse_host


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
            # 随机打乱脚本加载顺序
            random.shuffle(scripts)
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                vulns = {executor.submit(self.vuln, script): script for script in scripts}
                for future in concurrent.futures.as_completed(vulns, timeout=3):
                    future.result()
            self.out = list(filter(None, self.out))
            for i in self.out:
                console('Vuln', self.ip, i + '\n')

            Sqldb('result').get_vuln(self.ip, self.out)
        except (EOFError, concurrent.futures._base.TimeoutError):
            pass
        except Exception as e:
            logging.exception(e)


if __name__ == "__main__":
    start_time = time.time()
    Vuln(['127.0.0.1']).run()
    end_time = time.time()
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
