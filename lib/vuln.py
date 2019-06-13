# coding=utf-8

import glob
import importlib
import time
import os
import concurrent.futures


class Vuln():
    def __init__(self, host, ports, apps):
        host = host.replace('http://', '').replace('https://', '').rstrip('/')
        self.ip = host
        self.apps = apps
        self.ports = ports
        self.out = []

    def vuln(self, script):
        check_func = getattr(script, 'check')
        result = check_func(self.ip, self.ports, self.apps)
        if result:
            if type(result) == type('test'):
                self.out.append(result)
            else:
                self.out.extend(result)

    def run(self):
        scripts = []
        for _ in glob.glob('script/*.py'):
            script_name = os.path.basename(_).replace('.py', '')
            vuln = importlib.import_module('script.%s' % script_name)
            scripts.append(vuln)
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=50) as executor:
            executor.map(self.vuln, scripts)
        return self.out


if __name__ == "__main__":
    start_time = time.time()
    Vuln('127.0.0.1', ['Unknown:2375'], ["iis", "Apache", "jQuery"]).run()
    end_time = time.time()
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
