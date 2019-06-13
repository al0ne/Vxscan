# author: al0ne
# https://github.com/al0ne

import random
import socket
import struct
from fake_useragent import UserAgent

ua = UserAgent()
ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
HEADERS = {
    'Accept':
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'User-Agent': ua.random,
    'Referer': 'https://www.google.com',
    'X-Forwarded-For': ip,
    'X-Real-IP': ip,
    'Connection': 'keep-alive',
}

pyHEADERS = [
    'User-Agent: {}'.format(ua.random),
    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Referer: https://www.google.com', 'X-Forwarded-For: {}'.format(ip),
    'X-Real-IP: {}'.format(ip), 'Connection: close'
]

if __name__ == "__main__":
    print(HEADERS)