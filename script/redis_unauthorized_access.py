#!/usr/bin/python

import socket
from lib.verify import verify

vuln = ['redis', '6379']


def check(ip, ports, apps):
    if verify(vuln, ports, apps):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((ip, 6379))
            payload = b'\x2a\x31\x0d\x0a\x24\x34\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'
            s.send(payload)
            data = s.recv(1024)
            s.close()
            if b"redis_version" in data:
                return '6379 Redis Unauthorized Access'
        except Exception as e:
            s.close()
