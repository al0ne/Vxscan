# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import concurrent.futures
import subprocess
import re
import sys
import platform
import dns.resolver
from urllib import parse
from lib.sqldb import Sqldb
from lib.bcolors import bcolors
from lib.settings import PING, CHECK_DB

class ActiveCheck():
    def __init__(self, hosts):
        self.hosts = hosts
        self.out = []
    
    def check_db(self, hosts):
        self.out = Sqldb('result').query_db(hosts)
    
    def check(self, url):
        loc = parse.urlparse(url)
        if getattr(loc, 'netloc'):
            host = loc.netloc
        else:
            host = loc.path
        try:
            if not re.search(r'\d+\.\d+\.\d+\.\d+', host):
                dns.resolver.query(host, 'A')
            if PING:
                try:
                    if platform.system() == 'Windows':
                        subprocess.check_output(['ping', '-n', '2', '-w', '1', host])
                    else:
                        subprocess.check_output(['ping', '-c 2', '-W 1', host])
                    self.out.append(url)
                except Exception as e:
                    sys.stdout.write(bcolors.OKGREEN + "{} is not alive\n".format(host) + bcolors.ENDC)
                    return False
            else:
                self.out.append(url)
        except Exception as e:
            return False
    
    def pool(self):
        sys.stdout.write(bcolors.RED + "Start Ping ...\n\n" + bcolors.ENDC)
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(self.check, self.hosts)
        if CHECK_DB:
            self.check_db(list(set(self.out)))
        return self.out


if __name__ == "__main__":
    result = ActiveCheck(['www.baidu.com']).pool()
    print(result)
