# coding=utf-8

import hashlib
import logging
import random
import re
from urllib import parse

from lib.Requests import Requests
from lib.cli_output import console
from lib.url import parse_host

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
        ip = parse_host(ip)
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
            url = re.sub(r':443$|:80$', '', url)
            result.append(url)

    return list(set(result))


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


def verify_https(url):
    # 验证域名是http或者https的
    # 如果域名是302跳转 则获取跳转后的地址
    req = Requests()
    # noinspection PyBroadException
    if '://' in url:
        try:
            r = req.get(url)
            return url
        except Exception as e:
            pass
    host = parse_host(url)
    url2 = parse.urlparse(url)
    if url2.netloc:
        url = url2.netloc
    elif url2.path:
        url = url2.path
    # noinspection PyBroadException
    try:
        r = req.get('https://' + url)
        getattr(r, 'status_code')
        console('Verify', host, 'https://' + url + '\n')
        return 'https://' + url
    except AttributeError:
        # noinspection PyBroadException
        try:
            req.get('http://' + url)
            console('Verify', host, 'http://' + url + '\n')
            return 'http://' + url
        except Exception:
            pass
    except Exception as e:
        logging.exception(e)


def get_md5():
    plain = ''.join([random.choice('0123456789') for _ in range(8)])
    md5sum = hashlib.md5()
    md5sum.update(plain.encode('utf-8'))
    md5 = md5sum.hexdigest()
    return [plain, md5]


def verify_ext(apps):
    ext = []
    try:
        if 'IIS' in apps or 'Microsoft ASP.NET' in apps or 'ASPX' in apps or 'ASP' in apps:
            ext.extend(['asp', 'aspx'])
        if 'PHP' in apps or 'wamp' in apps or 'phpstudy' in apps or 'Apache' in apps:
            ext.append('php')
        if 'Apache Tomcat' in apps or 'JSP' in apps or 'Jboss' in apps or 'Weblogic' in apps:
            ext.append('jsp')
    except TypeError:
        pass
    except Exception as e:
        logging.exception(e)
    ext.extend(['txt', 'xml', 'html'])
    return ext


def verify_country(url):
    # 此过滤功能是为了过滤掉一些源码相同但是网站语言不一样的域名
    # 国家列表
    count = [
        r'^ad\.', r'^ae\.', r'^af\.', r'^ag\.', r'^ai\.', r'^al\.', r'^am\.', r'^ao\.', r'^ar\.', r'^at\.', r'^au\.',
        r'^az\.', r'^bb\.', r'^bd\.', r'^be\.', r'^bf\.', r'^bg\.', r'^bh\.', r'^bi\.', r'^bj\.', r'^bl\.', r'^bm\.',
        r'^bn\.', r'^bo\.', r'^br\.', r'^bs\.', r'^bw\.', r'^by\.', r'^bz\.', r'^ca\.', r'^cf\.', r'^cg\.', r'^ch\.',
        r'^ck\.', r'^cl\.', r'^cm\.', r'^cn\.', r'^co\.', r'^cr\.', r'^cs\.', r'^cu\.', r'^cy\.', r'^cz\.', r'^de\.',
        r'^dj\.', r'^dk\.', r'^do\.', r'^dz\.', r'^ec\.', r'^ee\.', r'^eg\.', r'^es\.', r'^et\.', r'^fi\.', r'^fj\.',
        r'^fr\.', r'^ga\.', r'^gb\.', r'^gd\.', r'^ge\.', r'^gf\.', r'^gh\.', r'^gi\.', r'^gm\.', r'^gn\.', r'^gr\.',
        r'^gt\.', r'^gu\.', r'^gy\.', r'^hk\.', r'^hn\.', r'^ht\.', r'^hu\.', r'^id\.', r'^ie\.', r'^il\.', r'^in\.',
        r'^iq\.', r'^ir\.', r'^is\.', r'^it\.', r'^jm\.', r'^jo\.', r'^jp\.', r'^ke\.', r'^kg\.', r'^kh\.', r'^kp\.',
        r'^kr\.', r'^kt\.', r'^kw\.', r'^kz\.', r'^la\.', r'^lb\.', r'^lc\.', r'^li\.', r'^lk\.', r'^lr\.', r'^ls\.',
        r'^lt\.', r'^lu\.', r'^lv\.', r'^ly\.', r'^ma\.', r'^mc\.', r'^md\.', r'^mg\.', r'^ml\.', r'^mm\.', r'^mn\.',
        r'^mo\.', r'^ms\.', r'^mt\.', r'^mu\.', r'^mv\.', r'^mw\.', r'^mx\.', r'^my\.', r'^mz\.', r'^na\.', r'^ne\.',
        r'^ng\.', r'^ni\.', r'^nl\.', r'^no\.', r'^np\.', r'^nr\.', r'^nz\.', r'^om\.', r'^pa\.', r'^pe\.', r'^pf\.',
        r'^pg\.', r'^ph\.', r'^pk\.', r'^pl\.', r'^pr\.', r'^pt\.', r'^py\.', r'^qa\.', r'^ro\.', r'^ru\.', r'^sa\.',
        r'^sb\.', r'^sc\.', r'^sd\.', r'^se\.', r'^sg\.', r'^si\.', r'^sk\.', r'^sl\.', r'^sm\.', r'^sn\.', r'^so\.',
        r'^sr\.', r'^st\.', r'^sv\.', r'^sy\.', r'^sz\.', r'^td\.', r'^tg\.', r'^th\.', r'^tj\.', r'^tm\.', r'^tn\.',
        r'^to\.', r'^tr\.', r'^tt\.', r'^tw\.', r'^tz\.', r'^ua\.', r'^ug\.', r'^us\.', r'^uy\.', r'^uz\.', r'^vc\.',
        r'^ve\.', r'^vn\.', r'^ye\.', r'^yu\.', r'^za\.', r'^zm\.', r'^zr\.', r'^zw\.', r'^en\.'
    ]

    if re.search(r'\d+\.\d+\.\d+\.\d+', url):
        return False

    for i in count:
        if re.search(i, url):
            return True

    return False
