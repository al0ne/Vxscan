# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import concurrent.futures
import subprocess
import re
import sys
import xml
import platform
import time
import nmap
import dns.resolver
import logging
from urllib import parse
from lib.verify import verify_country
from lib.cli_output import console
from lib.sqldb import Sqldb
from lib.settings import PING, CHECK_DB, VERIFY_COUNTRY


class ActiveCheck:
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

        # 验证国家
        if VERIFY_COUNTRY:
            if verify_country(host):
                console('PING', host, "Disable Country\n")
                return False

        try:
            # 判断是IP还是域名，域名的话需要检测域名解析
            if not re.search(r'\d+\.\d+\.\d+\.\d+', host):
                # 验证DNS存活并且DNS解析不能是一些特殊IP（DNSIP、内网IP）
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ['1.1.1.1', '8.8.8.8']
                a = resolver.query(host, 'A')
                for i in a.response.answer:
                    for j in i.items:
                        if hasattr(j, 'address'):
                            if re.search(r'1\.1\.1\.1|8\.8\.8\.8|127\.0\.0\.1|114\.114\.114\.114|0\.0\.0\.0',
                                         j.address):
                                return False
            if PING:
                try:
                    # Windows调用ping判断存活 Linux调用nmap来判断主机存活
                    # nmap判断存活会先进行ping然后连接80端口，这样不会漏掉
                    if platform.system() == 'Windows':
                        subprocess.check_output(['ping', '-n', '2', '-w', '1', host])
                        self.out.append(url)
                    else:
                        nm = nmap.PortScanner()
                        result = nm.scan(hosts=host, arguments='-sP -n')
                        for k, v in result.get('scan').items():
                            if not v.get('status').get('state') == 'up':
                                console('PING', host, "is not alive\n")
                                return False
                            else:
                                self.out.append(url)

                except (AttributeError, subprocess.CalledProcessError, xml.etree.ElementTree.ParseError,
                        nmap.nmap.PortScannerError):
                    console('PING', host, "is not alive\n")
                    return False
                except Exception as e:
                    logging.exception(e)
                    return False

            else:
                self.out.append(url)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            console('DnsCheck', host, "No A record\n")
        except dns.exception.Timeout:
            console('DnsCheck', host, "Timeout\n")
        except Exception as e:
            logging.exception(e)
            return False

    def disable(self):
        # 禁止扫描所有敏感域名，遵守法律！！！
        for i in self.out:
            if re.search(r'\.org\.cn|\.com\.cn|\.cn|gov\.cn|edu\.cn|\.mil|\.aero|\.int|\.go\.\w+$|\.ac\.\w+$', i):
                console('Disable', i, "Do not scan this domain\n\n")
                sys.exit(1)

    def pool(self):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                result = {executor.submit(self.check, i): i for i in self.hosts}
                for future in concurrent.futures.as_completed(result, timeout=3):
                    future.result()
        except (EOFError, concurrent.futures._base.TimeoutError):
            pass
        except Exception as e:
            logging.exception(e)

        if CHECK_DB:
            self.check_db(list(set(self.out)))

        self.disable()

        return self.out


if __name__ == "__main__":
    start_time = time.time()
    active_hosts = ActiveCheck(['127.0.0.1']).pool()
    end_time = time.time()
    print(active_hosts)
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
