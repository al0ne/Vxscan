# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import nmap
import logging


def osdetect(ip):
    logging.basicConfig(filename='error.log', level=logging.ERROR)
    nm = nmap.PortScanner()
    try:
        result = nm.scan(hosts=ip, arguments='-sS -O -vv -n -T4 -p 80,22,443')
        for k, v in result.get('scan').items():
            for i in v.get('osmatch'):
                return i.get('name')
    except Exception as e:
        logging.exception(e)


if __name__ == "__main__":
    os = osdetect('1.1.1.1')
    print(os)
