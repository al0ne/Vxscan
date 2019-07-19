# coding=utf-8

import re

apps = None
ports = ['CDN:0']
vuln = ['27017', 'Mongodb']


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


def get_hosts(ip, username):
    result = []
    password = []
    with open('data/password.txt', 'r', encoding='UTF-8') as f:
        for i in f.readlines():
            password.append(i.strip())
    for name in username:
        for passwd in password:
            result.append('{}|{}|{}'.format(ip, name, passwd))
    return result
