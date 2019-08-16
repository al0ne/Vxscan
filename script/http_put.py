import requests
import random
from lib.random_header import get_ua
from lib.verify import get_list


def put(url):
    url = url.strip('/')
    text = random.randint(100000000, 200000000)
    payload = '/{}.txt'.format(text)
    url = url + payload
    data = {'{}'.format(text): '{}'.format(text)}
    r = requests.put(url, data=data, allow_redirects=False, verify=False, headers=get_ua())
    if r.status_code == 201:
        return 'HTTP METHOD PUT url: {}'.format(url)


def check(url, ip, ports, apps):
    try:
        probe = get_list(ip, ports)
        for url in probe:
            result = put(url)
    except Exception as e:
        pass
    if result:
        return result
