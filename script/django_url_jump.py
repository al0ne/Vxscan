# author: al0ne
# https://github.com/al0ne

import requests
from lib.verify import get_list
from lib.random_header import HEADERS


def run(url):
    domain = 'example.com'
    r = requests.get(url + '//' + domain, allow_redirects=False, timeout=3, headers=HEADERS)
    if (r.status_code == 301) and (domain in r.headers['Location']) and url.strip('http://') not in r.headers[
        'Location']:
        return 'django url jump : ' + url


def check(ip, ports, apps):
    result = []
    probe = get_list(ip, ports)
    for i in probe:
        result.append(run(i))
    return result
