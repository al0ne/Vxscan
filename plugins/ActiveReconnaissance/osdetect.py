# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import nmap
import sys
from lib.bcolors import bcolors


def osdetect(ip):
    sys.stdout.write(bcolors.RED + "OS：\n" + bcolors.ENDC)
    nm = nmap.PortScanner()
    try:
        result = nm.scan(hosts=ip, arguments='-sS -O -vv -n -T4 -p 80,22,443')
        for k, v in result.get('scan').items():
            if v.get('osmatch'):
                for i in v.get('osmatch'):
                    sys.stdout.write(bcolors.OKGREEN + '[+] {}\n'.format(i.get('name')) + bcolors.ENDC)
                    return i.get('name')
            else:
                break
    except Exception as e:
        sys.stdout.write(bcolors.RED + "[+] None" + bcolors.ENDC)
        return None


if __name__ == "__main__":
    os = osdetect('127.0.0.1')