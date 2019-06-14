import socket
from lib.verify import verify

vuln = ['Memcached', '11211']


def check(ip, ports, apps):
    if verify(vuln, ports, apps):
        port = 11211
        payload = b'\x73\x74\x61\x74\x73\x0a'  # command:stats
        s = socket.socket()
        socket.setdefaulttimeout(5)
        try:
            s.connect((ip, port))
            s.send(payload)
            recvdata = s.recv(2048)  # response larger than 1024
            s.close()
            if recvdata and (b'STAT version' in recvdata):
                return '11211 Memcache Unauthorized Access'
        except Exception as e:
            pass
