# coding=utf-8

import re
import random
import base64
import itertools
import concurrent.futures
import difflib
import logging
from urllib import parse
from lib.sqldb import Sqldb
from lib.settings import *
from lib.cli_output import *
from lib.Requests import Requests


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
    def __init__(self, dbname):
        self.notstr = ''
        self.notlen = ''
        self.goto = ''
        self.title = ''
        self.dbname = dbname
        self.ext = 'asp,php'
        self.outjson = []
        
        self.req = Requests()
    
    def get_urls(self, domain):
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
            '/extra', '/file', '/qq', '/up', '/config', '/' + domain
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
        return set(path)
    
    def diff(self, text):
        result = difflib.SequenceMatcher(None, self.notstr, text).quick_ratio()
        return result
    
    def _verify(self, r, goto, title):
        result = True
        if r.status_code in BLOCK_CODE:
            result = False
        if r.headers['Content-Type'] in BLOCK_CONTYPE:
            result = False
        if len(r.text) == self.notlen:
            result = False
        if goto == self.goto:
            result = False
        for i in PAGE_404:
            if i in r.text:
                result = False
                break
        if title == self.title and title != 'None':
            result = False
        return result
    
    def check404(self, url):
        # 访问一个随机的页面记录404页面的长度与内容
        key = str(random.random() * 100)
        random_url = base64.b64encode(key.encode('utf-8'))
        url = url + '/' + random_url.decode(
            'utf-8') + '.html'
        try:
            r = self.req.get(url)
            self.notstr = r.text[:10000]
            self.notlen = len(r.text)
            if r.is_redirect:
                self.goto = r.headers['Location']
        except Exception as e:
            logging.exception(e)
    
    def scan(self, host):
        try:
            r = self.req.get(host)
            if r.is_redirect:
                goto = r.headers['Location']
            else:
                goto = 'test'
            if r.headers['Content-Type']:
                contype = re.sub('\w+/', '', str(r.headers['Content-Type']))
                contype = re.sub(';.*', '', contype)
            else:
                contype = 'None'
            text = r.text[:10000]
            title = re.search('(?<=<title>).*(?=</title>)', text)
            if self._verify(r, goto, title):
                if contype == 'html':
                    result = self.diff(text)
                else:
                    result = 0
                if result < 0.8:
                    if title == None:
                        title = 'None'
                    else:
                        title = title.group()
                    title = re.sub(r'\n|\t', '', title)
                    urlresult = parse.urlparse(host)
                    sys.stdout.write(bcolors.OKGREEN + '[+] {}{:^12}{:^14}\t{:^18}\t{:^8}\n'.format(
                        r.status_code, len(r.text), title, contype, str(r.url)) + bcolors.ENDC)
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
            pass
        return 'OK'
    
    def save(self, urls):
        Sqldb(self.dbname).get_urls(urls)
    
    def run(self, task):
        print(bcolors.RED + 'URLS：' + bcolors.ENDC)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=THREADS) as executor:
            futures = [executor.submit(self.scan, i) for i in task]
            for future in concurrent.futures.as_completed(futures):
                future.result()
        self.save(self.outjson)
    
    # 创建启动任务
    def pool(self, host):
        self.check404(host)
        task = []
        urls = self.get_urls(host)
        for url in urls:
            task.append(host + url)
        self.run(task)
