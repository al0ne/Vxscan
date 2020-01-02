import concurrent.futures
import logging
import re
from urllib import parse

from lxml import etree

from lib.Requests import Requests
from lib.cli_output import console
from lib.sqldb import Sqldb
from plugins.InformationGathering.js_leaks import JsLeaks


def dedup_url(urls):
    urls = list(set(urls))
    result = []
    okurl = []
    for i in urls:
        urlparse = parse.urlparse(i)
        path = urlparse.path
        if path and path.split('/')[-2]:
            key = path.split('/')[-2]
            if key not in result:
                result.append(key)
                okurl.append(i)
        else:
            okurl.append(i)
    return okurl


class Crawl:
    def __init__(self, host, dbname):
        self.urls = []
        self.js = []
        self.domain = ''
        self.dbname = dbname
        self.host = host
        self.result = []
        self.req = Requests()
    
    def jsparse(self, r):
        try:
            html = etree.HTML(r.text)
            result = html.xpath('//script/@src')
            for i in result:
                if not re.search(
                    r'jquery|bootstrap|adsbygoogle|angular|javascript|#|vue|react|51.la/=|map\.baidu\.com|canvas|cnzz\.com|slick\.js|autofill-event\.js|tld\.js|clipboard|Chart\.js',
                    i):
                    if '://' not in i:
                        i = re.sub(r'^/|^\.\./', '', i)
                        i = self.host + '/' + i
                    self.js.append(i)
        except (AttributeError, AttributeError, ValueError):
            pass
        except Exception as e:
            logging.exception(e)
    
    def extr(self, url, body):
        # html页面内提取邮箱
        email = re.findall(r'\b[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+', body)
        if email:
            self.result.extend(list(map(lambda x: 'URL: ' + url + '  Email: ' + x, email)))
        # html页面内提取手机号
        phone = re.findall(
            r'\b(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|199|170|171)[0-9]{8}\b',
            body)
        if phone:
            self.result.extend(list(map(lambda x: 'URL: ' + url + '  Phone: ' + x, phone)))
        # html注释内提取ip地址
        ipaddr = re.findall(
            r'(?<=<!--).*((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*(?=-->)',
            body)
        if ipaddr:
            self.result.extend(list(map(lambda x: 'IP: ' + x, ipaddr)))
        # html注释内提取https连接
        links = re.findall(r'(?<=<!--).{0,120}((?:http|https):[\w\./\?\-=&]+).{0,120}(?=-->)', body)
        if links:
            self.result.extend(list(map(lambda x: 'URL: ' + url + '  Links: ' + x, links)))
        # html注释内提取a连接
        links2 = re.findall(r'(?<=<!--).{0,120}a\shref="([\-\w\.\?:=\&/]+)".{0,120}(?=-->)', body)
        if links2:
            self.result.extend(list(map(lambda x: 'URL: ' + url + '  Links: ' + x, links2)))
        links3 = re.findall(
            r'(?<=<!--).{0,120}\b(?:usr|pwd|uname|uid|file|upload|manager|webadmin|backup|account|admin|password|pass|user|login|secret|private|crash|root|xxx|fix|todo|secret_key|token|auth_token|access_token|username|authkey|user_id|userid|apikey|api_key|sid|eid|passwd|session_key|SESSION_TOKEN|api_token|access_token_secret|private_key|DB_USERNAME|oauth_token|api_secret_key|备注|笔记|备份|后台|登陆|管理|上传|下载|挂马|挂链)\b.{0,120}(?=-->)',
            body)
        if links3:
            self.result.extend(list(map(lambda x: 'URL: ' + url + '  Links: ' + x, links3)))
    
    def parse_html(self, host):
        try:
            r = self.req.get(host)
            self.jsparse(r)
            self.extr(r.url, r.text)
            urlparse = parse.urlparse(host)
            domain = urlparse.netloc
            if not self.domain:
                self.domain = domain
            html = etree.HTML(r.text)
            result = html.xpath('//a/@href')
            for link in result:
                if not re.search('#|mail*|^/$|javascript', link):
                    if 'http' not in link:
                        if urlparse.netloc:
                            link = urlparse.scheme + '://' + urlparse.netloc + '/' + link
                        else:
                            link = 'http://' + host + '/' + link
                    if domain in link:
                        if '=' not in link:
                            self.urls.append(link)
        except (UnboundLocalError, AttributeError, ValueError):
            pass
        except Exception as e:
            logging.exception(e)
        
        self.urls = dedup_url(self.urls)
        
        return list(set(self.urls))
    
    def pool(self):
        result = self.parse_html(self.host)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
                futures = [executor.submit(self.parse_html, i) for i in result]
                for future in concurrent.futures.as_completed(futures, timeout=3):
                    future.result()
        except (EOFError, concurrent.futures._base.TimeoutError):
            pass
        except Exception as e:
            logging.exception(e)
        
        jslink = JsLeaks().pool(self.js)
        
        self.result.extend(jslink)
        self.result = list(set(self.result))
        
        for i in self.result:
            console('Crawl', self.host, i + '\n')
        
        Sqldb(self.dbname).get_crawl(self.domain, self.result)


if __name__ == "__main__":
    Crawl('https://www.baidu.com').pool()
