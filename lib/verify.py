# coding=utf-8

import re
from lib.settings import PASS

apps = None
ports = ['DNS:53', 'http:7001', 'ssh:22']
vuln = ['http', 'weblogic', '7001']


def verify(vuln, port, apps):
    if vuln[0] == 'True':
        return True
    vuln = list(map(lambda x: x.lower(), vuln))
    for i in port:
        server, port = i.split(':')
        if (server in vuln) or (port in vuln):
            return True
    if apps:
        apps = list(map(lambda x: x.lower(), apps))
        for _ in apps:
            if _ in vuln:
                return True
        return False


def get_list(ip, ports):
    result = []
    if ('http:80' in ports and 'http:443' in ports) or ('http:80' in ports and 'https:443' in ports):
        ports.remove('http:80')
    for i in ports:
        server, port = i.split(':')
        server = server.lower()
        if (server == 'http') and not (server == 'http' and port == '443'):
            url = server + '://' + ip + ':' + port
            if ':80' in url:
                url = re.sub(r':80$', '', url)
            result.append(url)
        if server == 'http' and port == '443':
            url = server + 's://' + ip + ':' + port
            url = re.sub(r':443', '', url)
            result.append(url)
        if server == 'https':
            url = server + '://' + ip + ':' + port
            url = re.sub(r':443$', '', url)
            result.append(url)

    return result


def get_hosts(ip, USER):
    result = []
    for name in USER:
        for passwd in PASS:
            result.append('{}|{}|{}'.format(ip, name, passwd))
    return result
