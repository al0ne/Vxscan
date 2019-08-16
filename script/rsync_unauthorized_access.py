from lib.verify import verify
import socket

timeout = 2

vuln = ['rsync', '873']


def check(url, ip, ports, apps):
    if verify(vuln, ports, apps):
        try:
            socket.setdefaulttimeout(1.5)
            payload = b"\x40\x52\x53\x59\x4e\x43\x44\x3a\x20\x33\x31\x2e\x30\x0a"
            socket.setdefaulttimeout(timeout)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_address = (ip, 873)
            sock.connect(server_address)
            sock.sendall(payload)
            initinfo = sock.recv(400)
            if b"RSYNCD" in initinfo:
                sock.sendall(b"\x0a")
            modulelist = sock.recv(200)
            sock.close()
            if len(modulelist) > 0:
                return '873 Rsync Unauthorized Access'
        except Exception as e:
            pass
            # return '27017 MongoDB fail'
