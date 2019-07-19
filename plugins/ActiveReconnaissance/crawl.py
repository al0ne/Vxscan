import concurrent.futures
import re
from lxml import html, etree
from lib.Requests import Requests
from urllib import parse
from plugins.InformationGathering.js_leaks import JsLeaks
from plugins.Vulnerability.lfi_sqli import SqlLfi


class crawl():
    def __init__(self, host):
        self.links = []
        self.urls = []
        self.js = []
        self.host = host
        self.result = []
        self.req = Requests()
    
    def jsparse(self, r):
        html = etree.HTML(r.text)
        result = html.xpath('//script/@src')
        for i in result:
            if not re.search('jquery|bootstrap|adsbygoogle|javascript|#|vue|react|51.la', i):
                if '://' not in i:
                    i = self.host + i
                self.js.append(i)
    
    def extr(self, body):
        email = re.search(r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+', body).group()
        if email:
            self.result.append('Email Leaks: {}'.format(email))
        phone = re.search(
            r'(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|199|170|171)[0-9]{8}',
            body).group()
        if phone:
            self.result.append('Phone Leaks: {}'.format(phone))
    
    def parse_html(self, host):
        try:
            exts = ['asp', 'php', 'jsp', 'do', 'aspx', 'action', 'do', 'html']
            r = self.req.get(host)
            self.jsparse(r)
            self.extr(r.text)
            tmp = html.document_fromstring(r.text)
            tmp.make_links_absolute(self.host)
            links = tmp.iterlinks()
            for i in links:
                i = i[2]
                ext = parse.urlparse(i)[2].split('.')[-1]
                if ext in exts:
                    # 带参数的直接加入列表，不带参数的需要二次访问
                    if re.search('=', i) or re.search('/\?\w+=\w+', i):
                        self.links.append(i)
                    else:
                        self.urls.append(i)
        except Exception as e:
            pass
        return list(set(self.urls))
    
    def pool(self):
        result = self.parse_html(self.host)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=30) as executor:
            executor.map(self.parse_html, result)
        jslink = JsLeaks().pool(self.js)
        sql = SqlLfi().pool(self.links)
        self.result.extend(jslink)
        self.result.extend(sql)
        return self.result