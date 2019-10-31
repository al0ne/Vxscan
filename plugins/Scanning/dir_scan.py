# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import re
import base64
import urllib3
import glob
import itertools
import concurrent.futures
import logging
import ssl
import chardet
import socket
import OpenSSL
import requests
import random
from urllib import parse
from bs4 import BeautifulSoup
from lib.verify import verify_ext
from lib.sqldb import Sqldb
from lib.settings import *
from lib.cli_output import *
from lib.Requests import Requests
from plugins.ActiveReconnaissance.robots import robots


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
    def __init__(self, dbname, apps, host):
        self.notstr = ''
        self.apps = apps
        self.notlen = ''
        self.goto = ''
        self.host = host
        self.title = ''
        self.dbname = dbname
        self.outjson = []

        self.req = Requests()

    def get_urls(self, domain):
        wordlist = []
        robot = robots(domain)
        domain = domain.replace('http://', '').replace('https://', '').rstrip('/')
        domain2 = re.sub(r'\.', '_', domain)
        domain3 = domain.strip('www.')
        ext = verify_ext(self.apps)
        ext = list(map(lambda x: '.' + x, ext))
        path = []
        for txt in glob.glob(r'data/path/*.txt'):
            with open(txt, 'r', encoding='utf-8') as f:
                for i in f.readlines():
                    path.append(i.strip())
        leaks = Cartesian()
        leaks.add_data([
            '/www',
            '/1',
            '/2016',
            '/2017',
            '/2018',
            '/2019',
            '/wwwroot',
            '/backup',
            '/index',
            '/web',
            '/test',
            '/tmp',
            '/default',
            '/temp',
            '/website',
            '/upload',
            '/bin',
            '/bbs',
            '/www1',
            '/www2',
            '/log',
            '/extra',
            '/file',
            '/qq',
            '/up',
            '/config',
            '/' + domain,
            '/userlist',
            '/dev',
            '/a',
            '/123',
            '/sysadmin',
            '/localhost',
            '/111',
            '/access',
            '/old',
            '/i',
            '/vip',
            '/index.php',
            '/global',
            '/key',
            '/webroot',
            '/out',
            '/server',
        ])
        leaks.add_data([
            '.tar.gz', '.zip', '.rar', '.sql', '.7z', '.bak', '.tar', '.txt', '.tgz', '.swp', '~', '.old', '.tar.bz2',
            '.data', '.csv'
        ])
        path.extend(leaks.build())
        index = Cartesian()
        index.add_data([
            '/1', '/l', '/info', '/index', '/admin', '/login', '/qq', '/q', '/search', '/install', '/default', '/cmd',
            '/upload', '/test', '/manage', '/loading', '/left', '/zzzz', '/welcome', '/ma', '/66'
        ])
        index.add_data(ext)
        path.extend(index.build())
        path.extend(wordlist)
        if robot:
            path.extend(robot)
        return list(set(path))

    def _verify(self, url, code, contype, length, goto, text, title):
        # 验证404页面
        try:
            result = True
            if code in BLOCK_CODE:
                result = False
            if contype in BLOCK_CONTYPE:
                result = False
            if length == self.notlen:
                result = False
            # 调转等于404页面的调转时
            if goto == self.goto:
                result = False
            # url在跳转路径中
            if (url in goto) or (goto in url):
                result = False
            if url.strip('/') == self.goto or url.strip('/') == goto:
                result = False
            for i in PAGE_404:
                if i in text:
                    result = False
                    break
            if title == self.title and title != 'None':
                result = False
            # 有些302跳转会在location里出现error或者404等关键字
            if re.search(r'forbidden|error|404', goto):
                result = False
            # 文件内容类型对不上的情况
            if re.search(r'\.bak$|\.zip$|\.rar$|\.7z$|\.old$|\.htaccess$|\.csv$|\.txt$|\.sql$|\.tar$|\.tar.gz$',
                         url) and contype == 'html':
                result = False
            return result
        except:
            return False

    def parse_html(self, text):
        result = []
        soup = BeautifulSoup(text, 'html.parser')
        for i in soup.find_all(['a', 'img', 'script']):
            if i.get('src'):
                result.append(i.get('src'))
            if i.get('href'):
                result.append(i.get('href'))
        return result

    def check404(self, url):
        # 访问一个随机的页面记录404页面的长度与内容
        key = str(random.random() * 100)
        random_url = base64.b64encode(key.encode('utf-8'))
        url = url + '/' + random_url.decode('utf-8') + '.html'
        try:
            self.notstr = '404page'
            r = self.req.get(url)
            if r.status_code == '200':
                coding = chardet.detect(r.content[:10000]).get('encoding')
                if coding:
                    text = r.content[:20000].decode(coding)
                    self.notstr = self.parse_html(text)
            self.notlen = r.headers.get('Content-Length')
            if not self.notlen:
                self.notlen = len(r.content)
            if r.is_redirect:
                self.goto = r.headers['Location']
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout,
                requests.exceptions.SSLError, requests.exceptions.ConnectionError, ssl.SSLError, AttributeError,
                ConnectionRefusedError, socket.timeout, urllib3.exceptions.ReadTimeoutError,
                urllib3.exceptions.ProtocolError, OpenSSL.SSL.WantReadError):
            pass

        except UnboundLocalError:
            pass

        except Exception as e:
            logging.exception(e)

    def scan(self, host):
        try:
            r = self.req.scan(host)
            if r.is_redirect:
                goto = r.headers.get('Location')
            else:
                goto = 'test'
            if r.headers.get('Content-Type'):
                contype = re.sub(r'\w+/', '', str(r.headers.get('Content-Type')))
                contype = re.sub(r';.*', '', contype)
            else:
                contype = 'None'
            rsp_len = r.headers.get('Content-Length')
            # 判断是不是网页或者文本，如果是其他文件coding将置为空
            ishtml = False
            if contype == 'html':
                ishtml = True
                content = r.raw.read()
            else:
                content = r.raw.read(25000)

            if ishtml:
                coding = chardet.detect(content).get('encoding')
                if coding:
                    text = content.decode(coding)
                    title = re.search('(?<=<title>).*(?=</title>)', text)
                else:
                    text = 'Other'
                    title = None

            else:
                text = 'Other'
                title = None
            if not rsp_len:
                rsp_len = len(content)

            urlresult = parse.urlparse(host)
            if self._verify(urlresult.path, r.status_code, contype, rsp_len, goto, text, title):
                result = 0
                if ishtml:
                    pagemd5 = self.parse_html(text)
                    if pagemd5 == self.notstr:
                        result = 1
                if result < 0.5:
                    if title is None:
                        title = 'None'
                    else:
                        title = title.group()
                    title = re.sub(r'\n|\t', '', title)
                    console('URLS', urlresult.netloc, urlresult.path + '\n')
                    data = {
                        urlresult.netloc: {
                            "rsp_code": r.status_code,
                            "rsp_len": rsp_len,
                            "title": title,
                            "contype": contype,
                            "url": urlresult.path
                        }
                    }
                    self.outjson.append(data)
                    r.close()

        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout,
                requests.exceptions.SSLError, requests.exceptions.ConnectionError, ssl.SSLError, AttributeError,
                ConnectionRefusedError, socket.timeout, urllib3.exceptions.ReadTimeoutError,
                urllib3.exceptions.ProtocolError, OpenSSL.SSL.WantReadError):
            pass

        except (UnboundLocalError, AttributeError):
            pass

        except Exception as e:
            logging.exception(host)
            logging.exception(e)

        try:
            r.close()
        except:
            pass
        return 'OK'

    def save(self, urls):
        Sqldb(self.dbname).get_urls(urls)

    def run(self, task):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
                futures = [executor.submit(self.scan, i) for i in task]
                for future in concurrent.futures.as_completed(futures, timeout=3):
                    future.result()

        except (EOFError, concurrent.futures._base.TimeoutError):
            pass

    # 创建启动任务
    def pool(self):
        host = self.host.strip('/')
        self.check404(host)
        task = []
        urls = self.get_urls(host)
        random.shuffle(urls)
        for url in urls:
            task.append(host + url)
        self.run(task)
        # 保存结果
        self.save(self.outjson)


if __name__ == "__main__":
    start_time = time.time()
    DirScan('result', ['php'], 'http://127.0.0.1').pool()
    end_time = time.time()
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
