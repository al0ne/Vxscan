from lib.Requests import Requests
from lib.verify import verify

vuln = ['Django']


def check(url, ip, ports, apps):
    req = Requests()
    if verify(vuln, ports, apps):
        payload = "//www.example.com"
        try:
            r = req.get(url + payload)
            if r.is_redirect and 'www.example.com' in r.headers.get('Location'):
                return 'Django < 2.0.8 任意URL跳转漏洞'
        except Exception as e:
            pass
