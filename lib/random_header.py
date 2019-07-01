# author: al0ne
# https://github.com/al0ne

import random
import socket
import struct
from fake_useragent import UserAgent


HEADERS = {
        'Accept':
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'User-Agent': "",
        'Referer': 'https://www.google.com',
        'X-Forwarded-For': "",
        'X-Real-IP': "",
        'Connection': 'keep-alive',
    }

def get_ua():
    ua = UserAgent()
    ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    HEADERS["User-Agent"] = ua.random
    HEADERS["X-Forwarded-For"] = HEADERS["X-Real-IP"] = ip
    pyHEADERS = [
        'User-Agent: {}'.format(ua.random),
        'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Referer: https://www.google.com', 'X-Forwarded-For: {}'.format(ip),
        'X-Real-IP: {}'.format(ip), 'Connection: close'
    ]
    return HEADERS


if __name__ == "__main__":
    print(get_ua())
