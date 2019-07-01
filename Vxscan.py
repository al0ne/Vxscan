# coding:utf-8

# author: al0ne
# https://github.com/al0ne

import os
import sys

if sys.version_info.major < 3:
    sys.stdout.write("Sorry, Vxscan requires Python 3.x\n")
    sys.exit(1)
sys.path.append(os.getcwd())
import re
import random
import argparse
import base64
import tqdm
import requests
import pyfiglet
import json
import ipaddress
import urllib3
import itertools
import concurrent.futures
import difflib
import logging
from urllib import parse
from lib.settings import *
from lib.random_header import get_ua
from lib.common import start, bcolors
from lib.save_html import save_html
from lib.active import ActiveCheck

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()
logging.basicConfig(filename='error.log',
                    format='%(asctime)s - %(pathname)s[line:%(lineno)d] - %(levelname)s: %(message)s',
                    level=logging.WARNING)


def read_file(file, word, ext):
    hosts = []
    file_scan = DirScan(word, ext)
    with open(file, 'rt') as f:
        for ip in f.readlines():
            hosts.append(ip.strip())
    file_scan.pool(hosts)


class Cartesian(object):
    def __init__(self):
        self._data_list = []
    
    # 添加生成笛卡尔积的数据列表
    def add_data(self, data=[]):
        self._data_list.append(data)
    
    # 计算笛卡尔积
    def build(self):
        urls = []
        for item in itertools.product(*self._data_list):
            urls.append(item[0] + item[1])
        return urls


class DirScan():
    def __init__(self, word, ext):
        self.notstr = ''
        self.notlen = ''
        self.goto = ''
        self.hosts = []
        self.urls = []
        self.outjson = []
        self.wordlist = word
        self.ext = ext
        self.waf = []
    
    def get_urls(self, domain):
        if self.ext is None:
            self.ext = 'jsp,php,asp,html'
        wordlist = []
        if self.wordlist != None:
            with open(self.wordlist, 'r') as f:
                for i in f.readlines():
                    aux = i.strip()
                    aux = aux if aux.startswith("/") else ("/"+aux)
                    wordlist.append(aux)
        domain = domain.replace('http://', '').replace('https://', '').rstrip('/')
        ext = self.ext.split(',')
        ext = list(map(lambda x: '.' + x, ext))
        path = [
            "/robots.txt", "/README.md", "/crossdomain.xml", "/.git/config",
            "/.hg"
            "/.git/index", "/.svn/entries", "/.svn/wc.db", "/.DS_Store",
            "/CVS/Root", "/CVS/Entries", "/.idea/workspace.xml",
            "/nginx_status", "/.mysql_history", "/login/", "/phpMyAdmin",
            "/pma/", "/pmd/", "/SiteServer", "/admin/", "/Admin/", "/manage",
            "/manager/", "/manage/html", "/resin-admin", "/resin-doc",
            "/axis2-admin", "/admin-console", "/system", "/wp-admin",
            "/uc_server", "/debug", "/Conf", "/webmail", "/service",
            "/memadmin", "/owa", "/harbor", "/master", "/root", "/xmlrpc.php",
            "/phpinfo.php", "/zabbix", "/api", "/backup", "/inc",
            "/web.config", "/httpd.conf", "/local.conf", "/sitemap.xml",
            "/app.config", "/.bash_history", "/.rediscli_history", "/.bashrc",
            "/.history", "/nohup.out", "/.mysql_history", "/server-status",
            "/solr/", "/examples/",
            "/examples/servlets/servlet/SessionExample", "/manager/html",
            "/login.do", "/config/database.yml", "/database.yml", "/db.conf",
            "/db.ini", "/jmx-console/HtmlAdaptor", "/cacti/",
            "/jenkins/script", "/memadmin/index.php", "/pma/index.php",
            "/phpMyAdmin/index.php", "/.git/HEAD", "/.gitignore",
            "/.ssh/known_hosts", "/.ssh/id_rsa", "/id_rsa",
            "/.ssh/authorized_keys", "/app.cfg", "/.mysql.php.swp",
            "/.db.php.swp", "/.database.php.swp", "/.settings.php.swp",
            "/.config.php.swp", "/config/.config.php.swp",
            "/.config.inc.php.swp", "/config.inc.php.bak", "/php.ini",
            "/sftp-config.json", "/WEB-INF/web.xml",
            "/WEB-INF/web.xml.bak", "/WEB-INF/config.xml",
            "/WEB-INF/struts-config.xml", "/server.xml",
            "/config/database.yml", "/WEB-INF/database.properties",
            "/WEB-INF/log4j.properties", "/WEB-INF/config/dbconfig",
            "/fckeditor/_samples/default.html", "/ckeditor/samples/",
            "/ueditor/ueditor.config.js",
            "/javax.faces.resource...%2fWEB-INF/web.xml.jsf", "/wp-config.php",
            "/configuration.php", "/sites/default/settings.php", "/config.php",
            "/config.inc.php", "/data/config.php", "/data/config.inc.php",
            "/data/common.inc.php", "/include/config.inc.php",
            "/WEB-INF/classes/", "/WEB-INF/lib/", "/WEB-INF/src/", "/.bzr",
            "/SearchPublicRegistries.jsp", "/.bash_logout",
            "/resin-doc/resource/tutorial/jndi-appconfig/test?inputFile=/etc/profile",
            "/test2.html", "/conf.ini", "/index.tar.tz", "/index.cgi.bak",
            "/WEB-INF/classes/struts.xml", "/package.rar",
            "/WEB-INF/applicationContext.xml", "/mysql.php", "/apc.php",
            "/zabbix/", "/script", "/editor/ckeditor/samples/", "/upfile.php",
            "/conf.tar.gz",
            "/WEB-INF/classes/conf/spring/applicationContext-datasource.xml",
            "/output.tar.gz", "/.vimrc", "/INSTALL.TXT", "/pool.sh",
            "/database.sql.gz", "/o.tar.gz", "/upload.sh",
            "/WEB-INF/classes/dataBase.properties", "/b.php", "/setup.sh",
            "/db.php.bak", "/WEB-INF/classes/conf/jdbc.properties",
            "/WEB-INF/spring.xml", "/.htaccess",
            "/resin-doc/viewfile/?contextpath=/&servletpath=&file=index.jsp",
            "/.htpasswd", "/id_dsa", "/WEB-INF/conf/activemq.xml",
            "/config/config.php", "/.idea/modules.xml",
            "/WEB-INF/spring-cfg/applicationContext.xml", "/test2.txt",
            "/WEB-INF/classes/applicationContext.xml",
            "/WEB-INF/conf/database_config.properties",
            "/WEB-INF/classes/rabbitmq.xml",
            "/ckeditor/samples/sample_posteddata.php", "/proxy.pac",
            "/sql.php", "/test2.php", "/build.tar.gz",
            "/WEB-INF/classes/config/applicationContext.xml",
            "/WEB-INF/dwr.xml", "/readme", "/phpmyadmin/index.php",
            "/WEB-INF/web.properties", "/readme.html", "/key"
        ]
        leaks = Cartesian()
        leaks.add_data([
            '/www', '/1', '/2016', '/2017', '/2018', '/2019', '/wwwroot',
            '/backup', '/index', '/web', '/test', '/tmp', '/default', '/temp',
            '/extra', '/file', '/qq', '/up', '/config', '/' + domain,
        ])
        leaks.add_data([
            '.tar.gz', '.zip', '.rar', '.sql', '.7z', '.bak', '.tar', '.txt',
            '.log', '.tmp', '.gz', '.bak~', '.sh'
        ])
        path.extend(leaks.build())
        index = Cartesian()
        index.add_data([
            '/1', '/l', '/info', '/index', '/admin', '/login', '/qq', '/q',
            '/shell', '/p', '/a', '/userinfo', '/api', '/common', '/web',
            '/manage', '/loading', '/left', '/zzzz', '/welcome', '/ma', '/66'
        ])
        index.add_data(ext)
        path.extend(index.build())
        path.extend(wordlist)
        return set(path)
    
    def check404(self, url, text):
        url = parse.urlparse(url)
        result = 0
        if url.netloc not in self.hosts:
            key = str(random.random() * 100)
            random_url = base64.b64encode(key.encode('utf-8'))
            host = url.scheme + '://' + url.netloc + '/' + random_url.decode(
                'utf-8') + '.html'
            try:
                r = requests.get(
                    host,
                    timeout=TIMEOUT,
                    verify=False,
                    headers=get_ua(),
                    allow_redirects=False)
                self.notstr = r.text[:10000]
                self.notlen = len(r.text)
                if r.is_redirect:
                    self.goto = r.headers['Location']
                self.hosts.append(url.netloc)
            except Exception as e:
                logging.exception(e)
        else:
            result = difflib.SequenceMatcher(None, self.notstr,
                                             text).quick_ratio()
        return result
    
    def save(self, out):
        outjson = []
        with open('report/result.json', 'w') as f:
            dic = {}
            if out:
                for _ in out:
                    for k1, v1 in _.items():
                        dic.setdefault(k1, []).append(v1)
            for i in self.waf:
                for k3, v3 in i.items():
                    if k3 in dic:
                        for k2, v2 in dic.items():
                            if k2 == k3:
                                data = {
                                    k3: {
                                        'WAF': v3.get('WAF'),
                                        'Webinfo': v3.get('Webinfo'),
                                        'Ports': v3.get('Ports'),
                                        'Ipaddr': v3.get('Ipaddr'),
                                        'Address': v3.get('Address'),
                                        'Vuln': v3.get('Vuln'),
                                        'URLS': v2
                                    }
                                }
                                outjson.append(data)
                    else:
                        outjson.append(i)
            json.dump(outjson, f, ensure_ascii=False, indent=4)
            save_html(outjson, html_name)
    
    def get_proto(self, ports):
        result = []
        try:
            for k, v in ports.items():
                for i in v.get('Ports'):
                    proto, port = i.split(':')
                    if not (proto == 'http' and port == '443'):
                        url = proto + '://' + k + ':' + port
                        url = re.sub(':80$', '', url)
                        if re.search('http|https', url):
                            result.append(url)
        except:
            pass
        return result
    
    def scan(self, host):
        try:
            session = requests.Session()
            HEADERS = get_ua()
            HEADERS.update(COOKIE)
            session.headers.update(HEADERS)
            r = session.get(
                host,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            if r.is_redirect:
                goto = r.headers['Location']
            else:
                goto = 'test'
            # 判断逻辑：1.排除无效状态吗 2.排除无效内容类型 3.判断302跳转
            # 4. 判断302跳转不能等于首页 5. 判断内容长度不等于404页面长度
            if (r.status_code not in BLOCK_CODE) and (
                r.headers['Content-Type'] not in BLOCK_CONTYPE) and (
                goto != self.goto) and (parse.urlparse(
                r.url).netloc not in parse.urlparse(goto).netloc) and (self.notlen != len(r.text)):
                text = r.text[:10000]
                title = re.search('(?<=<title>).*(?=</title>)', text)
                contype = re.sub('\w+/', '', str(r.headers['Content-Type']))
                contype = re.sub(';.*', '', contype)
                if contype == 'html':
                    result = self.check404(host, text)
                else:
                    result = 0
                if result < 0.8:
                    if title == None:
                        title = 'None'
                    else:
                        title = title.group()
                    title = re.sub(r'\n|\t', '', title)
                    urlresult = parse.urlparse(host)
                    tqdm.tqdm.write(bcolors.OKGREEN + "[+] " + bcolors.ENDC + '{}{:^12}{:^14}\t{:^18}\t{:^8}'.format(
                        r.status_code, len(r.text), title, contype,
                        str(r.url)))
                    data = {
                        urlresult.netloc: {
                            "rsp_code": r.status_code,
                            "rsp_len": len(r.text),
                            "title": title,
                            "contype": contype,
                            "url": urlresult.path
                        }
                    }
                    self.outjson.append(data)
        except Exception as e:
            logging.exception(e)
        return 'OK'
    
    def run(self, task):
        global THREADS
        print(bcolors.RED + '\nURLS：' + bcolors.ENDC)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=THREADS) as executor:
            futures = [executor.submit(self.scan, i) for i in task]
            for future in tqdm.tqdm(
                concurrent.futures.as_completed(futures),
                total=len(futures)):
                future.result()
    
    # 创建启动任务
    def pool(self, hosts):
        task = []
        # 通过socket与ping命令验证ip存活与域名解析
        hosts2 = ActiveCheck(hosts).pool()
        try:
            for host in hosts2:
                host = host.strip('/')
                if not re.search('http://|https://', host):
                    host = 'http://' + host
                name, wafresult = start(host)
                self.waf.append(name)
                if wafresult != 'NoWAF':
                    continue
                if not SKIP:
                    proto = self.get_proto(name)
                    for i in proto:
                        urls = self.get_urls(i)
                        for url in urls:
                            task.append(i + url)
            if task:
                self.run(task)
            self.save(self.outjson)
        except Exception as e:
            logging.exception(e)


if __name__ == "__main__":
    ascii_banner = pyfiglet.figlet_format("Vxscan")
    print(bcolors.RED + ascii_banner + bcolors.ENDC)
    start_time = time.time()
    parser = argparse.ArgumentParser(description='Vxscan V1.0')
    parser.add_argument(
        "-u", "--url", help='Start scanning url -u xxx.com or -u url1,url2')
    parser.add_argument("-f", "--file", help='read the url from the file')
    parser.add_argument("-t", "--threads", help='Set scan thread, default 150')
    parser.add_argument("-e", "--ext", help='Set scan suffix, -e php,asp')
    parser.add_argument("-i", "--inet", help='cidr eg. 1.1.1.1 or 1.1.1.0/24')
    parser.add_argument("-w", "--word", help='Read the dict from the file')
    parser.add_argument("--cookie", help='add a cookies')
    parser.add_argument(
        "-j", "--json", help='Read url from json file generated by tcpscan')
    args = parser.parse_args()
    dirscan = DirScan(args.word, args.ext)
    if args.word:
        SKIP = False
    if args.cookie:
        COOKIE = {"Cookie": args.cookie}
        HEADERS = get_ua()
        HEADERS.update(COOKIE)
    if args.inet:
        _ = []
        try:
            net = list(ipaddress.ip_network(args.inet).hosts())
            for i in net:
                _.append(str(i))
            dirscan.pool(_)
        except Exception as e:
            print("The task could not be carried out. {}".format(str(e)))
    if args.threads:
        try:
            THREADS = int(args.threads)
        except:
            print("Threads must be an int")
            print(THREADS)
    if args.url:
        dirscan.pool(args.url.split(","))
    if args.file:
        read_file(args.file, args.word, args.ext)
    end_time = time.time()
    if args.file or args.url:
        print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
    elif not args.inet:
        print('No scan url, Please start scanning with -u or -f')
