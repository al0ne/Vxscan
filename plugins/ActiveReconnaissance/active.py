# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import concurrent.futures
import subprocess
import re
import sys
import platform
import dns.resolver
import logging
from urllib import parse
from lib.cli_output import console
from lib.sqldb import Sqldb
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
                except subprocess.CalledProcessError:
                    console('PING', host, "is not alive\n")
                    return False
                except Exception as e:
                    logging.exception(e)
            
            else:
                self.out.append(url)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            console('DnsCheck', host, "No A record\n")
        except Exception as e:
            logging.exception(e)
            return False
    
    def disable(self):
        # 求生欲名单
        # 禁止扫描所有gov.cn与edu.cn结尾的域名，遵守法律！！！
        for i in self.out:
            if re.search(r'gov\.cn|edu\.cn$', i):
                console('Disable', i, "Do not scan this domain\n")
                sys.exit(1)
    
    def pool(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(self.check, self.hosts)
        if CHECK_DB:
            self.check_db(list(set(self.out)))
        self.disable()
        return self.out


if __name__ == "__main__":
    result = ActiveCheck(['www.github.com']).pool()
    print(result)
