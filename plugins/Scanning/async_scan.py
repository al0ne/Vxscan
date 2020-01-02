# coding:utf-8
# author: al0ne
# https://github.com/al0ne

import asyncio
import concurrent.futures
import glob
import itertools
import logging
import platform
import random
import re
import time

import aiohttp
import chardet

from lib.Requests import Requests
from lib.cli_output import console
from lib.random_header import get_ua
from lib.settings import *
from lib.sqldb import Sqldb
from lib.verify import verify_ext

if platform.system() != 'Windows':
    import uvloop
    
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    LIMIT = 800
else:
    LIMIT = 200


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


class DirScan:
    def __init__(self, dbname, apps, host, title):
        self.dbname = dbname
        self.apps = apps
        self.title = title
        self.headers = get_ua()
        self.outjson = []
        self.wordlist = []
        self.host = host
        self.urls = self.get_urls(self.host)
        self.req = Requests()
        
        # url请求随机顺序 避免溯源
        random.shuffle(self.urls)
    
    def get_urls(self, domain):
        wordlist = []
        domain = domain.replace('http://', '').replace('https://', '').rstrip('/')
        ext = verify_ext(self.apps)
        ext = list(map(lambda x: '.' + x, ext))
        path = []
        for txt in glob.glob(r'data/path/*.txt'):
            with open(txt, 'r', encoding='utf-8') as f:
                for i in f.readlines():
                    path.append(i.strip())
        domain2 = re.sub(r'\.', '_', domain)
        domain3 = domain.strip('www.')
        leaks = Cartesian()
        leaks.add_data([
            '/www', '/1', '/2016', '/2017', '/2018', '/2019', '/wwwroot', '/backup', '/index', '/web', '/test', '/tmp',
            '/default', '/temp', '/data', '/dump', '/database', '/web', '/ftp', '/sql', '/data', '/website', '/upload',
            '/bin', '/bbs', '/www1', '/www2', '/log', '/site', '/2', '/htdocs', '/w', '/back', '/admin', '/export',
            '/extra', '/file', '/qq', '/up', '/config', '/' + domain, '/userlist', '/dev', '/a', '/123', '/sysadmin',
            '/localhost', '/shop', '/sys', '/root', '/install', '/webserver', '/users', '/111', '/access', '/old', '/i',
            '/vip', '/index.php', '/global', '/key', '/webroot', '/out', '/server', '/db', '/备份', '/新建文件夹', '/网站',
            '/uc_server', '/beifen', '/joomla', '/login', '/crack', '/wangzhan', '/' + domain2, '/' + domain3, '/list'
        ])
        leaks.add_data([
            '.tar.gz', '.zip', '.rar', '.sql', '.7z', '.bak', '.tar', '.txt', '.tgz', '.swp', '~', '.old', '.tar.bz2',
            '.data', '.csv', '.log', '.tmp', '.gz', '.bak~', '.sh', '.rar', '.war', '.bk', '.tmp', '.arj', '.xz',
            '.bz2', '.apk'
        ])
        path.extend(leaks.build())
        index = Cartesian()
        index.add_data([
            '/1', '/l', '/info', '/index', '/admin', '/login', '/qq', '/q', '/search', '/install', '/default', '/cmd',
            '/upload', '/test', '/shell', '/p', '/a', '/userinfo', '/api', '/common', '/web', '/manage', '/loading',
            '/left', '/zzzz', '/welcome', '/ma', '/66', '/c', '/2', '/fuck', '/11', '/error', '/403', '/123', '/3',
            '/css', '/x', '/md5', '/xx', '/out', '/config', '/asd', '/result', '/conn', '/password', '/cmdshell', '/k',
            '/s', '/test1', '/up', '/xxxx', '/exp', '/shell1', '/shell2', '/i', '/aa', '/2011', '/2012', '/2013',
            '/2016', '/2017', '/2018', '/2019', '/dama', '/list', '/list2', '/caidao', '/anonymous', '/xianf'
        ])
        index.add_data(ext)
        path.extend(index.build())
        path.extend(wordlist)
        return list(set(path))
    
    def _verify(self, url, code, contype, title, length, goto, text):
        
        # 验证404页面
        try:
            
            result = True
            
            if code in BLOCK_CODE:
                result = False
            
            if contype in BLOCK_CONTYPE:
                result = False
            
            # 访问过快可能会出现拦截,从title过滤
            if re.search(r'Error|antispam|IP限制|访问禁止|小伙伴出错了|文档已移动|活动暂时关闭|Object moved|网站防火墙|访问被拦截|系统发生错误|404', title):
                result = False
            
            # 扫描的url标题里不能出现域名
            if re.search(
                r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:biz|cc|club|cn|com|co|edu|fun|group|info|ink|kim|link|live|ltd|mobi|net|online|org|pro|pub|red|ren|shop|site|store|tech|top|tv|vip|wang|wiki|work|xin|xyz|me))',
                title):
                result = False
            
            # 被WAF拦截的页面
            if re.search(r'Blocked by[\w\s]+waf|^false$|^post2$', text):
                result = False
            
            # 扫描url标题不能等于网站标题
            if self.title == title:
                result = False
            
            if title == 'None' and code == 0 and contype == 'None':
                result = False
            
            if re.sub('http://', 'https://', url) == goto:
                result = False
            
            for i in PAGE_404:
                if i in text:
                    result = False
                    break
            
            # 有些302跳转会在location里出现error或者404等关键字
            if re.search(r'forbidden|error|404', goto):
                result = False
            
            if code == 302 or code == 301:
                result = False
            
            # 跳转到路径
            if re.search(r'http://.*/\w+/$', goto):
                result = True
            
            # 有些报错页面不能排除掉
            if re.search(r'系统发生错误|PHP Error|PHP Parse error|database error|Error Message|Index of|mysql error', text):
                result = True
            
            # 文件内容类型对不上的情况
            if not (not re.search(
                r'\.bak$|\.zip$|\.rar$|\.7z$|\.old$|\.htaccess$|\.csv$|\.txt$|\.sql$|\.tar$|\.tar.gz$|\.tgz$|\.log$|\.gz$|\.data$|\.bz2$|\.sh$|\w+~$|\.bzr|\.DS_Store|\.xz$|\.db$',
                url) or not (contype == 'html')):
                result = False
            
            return result
        
        except Exception as e:
            logging.exception(e)
            return False
    
    def save(self, urls):
        Sqldb(self.dbname).get_urls(urls)
    
    async def scan(self, host, url, session):
        try:
            async with session.get(
                host + url,
                headers=self.headers,
                allow_redirects=False,
            ) as resp:
                # 判断是不是302跳转
                if resp.headers.get('Location'):
                    goto = resp.headers.get('Location')
                else:
                    goto = 'test'
                # 判断内容类型
                if resp.headers.get('Content-Type'):
                    contype = re.sub(r'\w+/', '', str(resp.headers.get('Content-Type')))
                    contype = re.sub(r';.*', '', contype)
                else:
                    contype = 'None'
                
                # 判断是不是网页或者文本，如果是其他文件coding将置为空
                ishtml = False
                
                try:
                    if contype == 'html':
                        ishtml = True
                        content = await resp.content.read(20000)
                    else:
                        content = b''
                except aiohttp.client_exceptions.ClientPayloadError:
                    pass
                
                # 获取html编码并解码
                if ishtml:
                    try:
                        coding = chardet.detect(content).get('encoding')
                        if coding:
                            # 如果能获取到编码则获取响应体并匹配标题
                            text = content.decode(coding)
                            title = re.search('(?<=<title>).*(?=</title>)', text)
                            # 匹配标题，如果不能匹配到标题则去响应体的前30位当做标题
                            if title:
                                title = title.group()
                            else:
                                title = text[:35]
                        else:
                            text = 'Other'
                            title = None
                    except Exception as e:
                        text = 'Other'
                        title = None
                        logging.exception(e)
                else:
                    text = 'Other'
                    title = None
                
                if title is None:
                    title = 'None'
                
                title = re.sub(r'\n|\t', '', title)
                
                # 获取响应长度
                rsp_len = resp.headers.get('Content-Length')
                if not rsp_len:
                    rsp_len = len(content)
                
                host2 = host.replace('http://', '').replace('https://', '').rstrip('/')
                
                if self._verify(url, resp.status, contype, title, rsp_len, goto, text):
                    console('URLS', host2, url + '\n')
                    data = {
                        host2: {
                            "rsp_code": resp.status,
                            "rsp_len": rsp_len,
                            "title": title,
                            "contype": contype,
                            "url": host + url
                        }
                    }
                    self.outjson.append(data)
        
        except (aiohttp.client_exceptions.ServerTimeoutError, ConnectionResetError,
                aiohttp.client_exceptions.ClientConnectorError, UnicodeDecodeError,
                aiohttp.client_exceptions.ClientOSError, aiohttp.client_exceptions.ServerDisconnectedError,
                concurrent.futures._base.TimeoutError, aiohttp.client_exceptions.ClientPayloadError):
            pass
        
        except Exception as e:
            logging.exception(e)
        
        return 'OK'
    
    async def run(self, host):
        tasks = []
        # 默认limit=100，enable_cleanup_closed设置为True防止ssl泄露，ttl_dns_cache调高dns缓存
        conn = aiohttp.TCPConnector(
            limit=LIMIT,
            enable_cleanup_closed=True,
            ttl_dns_cache=100,
            ssl=False,
        )
        timeout = aiohttp.ClientTimeout(total=60, connect=2)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            for url in self.urls:
                task = asyncio.ensure_future(self.scan(host, url, session))
                tasks.append(task)
            # gather方法是所有请求完成后才有输出
            _ = await asyncio.gather(*tasks)
            # for i in asyncio.as_completed(tasks):  # 类似于线程池中的task一样
            #     answer = await i
    
    # 创建启动任务
    def pool(self):
        loop = asyncio.get_event_loop()
        future = asyncio.ensure_future(self.run(self.host))
        loop.run_until_complete(future)
        
        self.save(self.outjson)


if __name__ == "__main__":
    start_time = time.time()
    scan = DirScan('result', ['php'], 'http://127.0.0.1', '')
    print(len(scan.get_urls('www.baidu.com')))
    end_time = time.time()
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
