import concurrent.futures
import re
import logging
from lib.cli_output import console
from lxml import etree
from lib.Requests import Requests
from urllib import parse
from lib.url import dedup_link
from lib.sqldb import Sqldb
from plugins.InformationGathering.js_leaks import JsLeaks


class crawl():
    def __init__(self, host):
        self.links = []
        self.urls = []
        self.js = []
        self.domain = ''
        self.host = host
        self.result = []
        self.req = Requests()
    
    def jsparse(self, r):
        try:
            html = etree.HTML(r.text)
            result = html.xpath('//script/@src')
            for i in result:
                if not re.search(r'jquery|bootstrap|adsbygoogle|javascript|#|vue|react|51.la/=', i):
                    if '://' not in i:
                        i = re.sub(r'^/|^\.\./', '', i)
                        i = self.host + '/' + i
                    self.js.append(i)
        except (AttributeError, AttributeError, ValueError):
            pass
        except Exception as e:
            logging.exception(e)
    
    def dedup_url(self, urls):
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
    
    def extr(self, url, body):
        email = re.findall(r'\b[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+', body)
        if email:
            self.result.extend(list(map(lambda x: 'URL: ' + url + '  Email: ' + x, email)))
        phone = re.findall(
            r'\b(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|199|170|171)[0-9]{8}\b',
            body)
        if phone:
            self.result.extend(list(map(lambda x: 'URL: ' + url + '  Phone: ' + x, phone)))
        ipaddr = re.findall(
            r'(?<=<!--).*((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)).*(?=-->)',
            body)
        if ipaddr:
            self.result.extend(list(map(lambda x: 'IP: ' + x, ipaddr)))
        links = re.findall(r'(?<=<!--).*((?:http|https):[\w\./\?=&]+)".*(?=-->)', body)
        if links:
            self.result.extend(list(map(lambda x: 'Links: ' + x, links)))
        links2 = re.findall(r'(?<=<!--).*a\shref="([\w\.\?=\&/]+)".*(?=-->)', body)
        if links2:
            self.result.extend(list(map(lambda x: 'Links: ' + x, links2)))
    
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
                        # 带参数的直接加入列表，不带参数的需要二次访问
                        if re.search('=', link) or re.search(r'/\?\w+=\w+', link):
                            self.links.append(link)
                        else:
                            self.urls.append(link)
        except (UnboundLocalError, AttributeError):
            pass
        except Exception as e:
            logging.exception(e)
        self.urls = self.dedup_url(self.urls)
        return list(set(self.urls))
    
    def pool(self):
        result = self.parse_html(self.host)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=30) as executor:
            executor.map(self.parse_html, result)
        jslink = JsLeaks().pool(self.js)
        self.result.extend(jslink)
        self.links = dedup_link(self.links)
        self.links = list(map(lambda x: 'Dynamic: ' + x, self.links))
        self.result.extend(self.links)
        self.result = list(set(self.result))
        for i in self.result:
            console('Crawl', self.host, i + '\n')
        Sqldb('result').get_crawl(self.domain, self.result)
