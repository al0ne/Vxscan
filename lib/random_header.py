# author: al0ne
# https://github.com/al0ne

import random
import socket
import string
import struct
from fake_useragent import UserAgent

HEADERS = {
    'Accept':
        'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'User-Agent': "",
    'Referer': "",
    'X-Forwarded-For': "",
    'X-Real-IP': "",
    'Accept-Encoding': "",
    'Connection': 'keep-alive',
}


def get_ua():
    ua = UserAgent()
    key = random.random() * 20
    referer = ''.join([random.choice(string.ascii_letters + string.digits) for x in range(int(key))])
    referer = 'www.' + referer.lower() + '.com'
    ip = socket.inet_ntoa(struct.pack('>I', random.randint(1, 0xffffffff)))
    HEADERS["User-Agent"] = ua.random
    HEADERS["Referer"] = referer
    HEADERS["X-Forwarded-For"] = HEADERS["X-Real-IP"] = ip
    
    return HEADERS


if __name__ == "__main__":
    print(get_ua())
