# coding=utf-8

from lib.random_header import get_ua
from lib.settings import TIMEOUT, COOKIE, SOCKS5
import requests
import urllib3
import re
import socks
import socket


class Requests():
    
    def __init__(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings()
        
        self.timeout = TIMEOUT
        self.session = requests.Session()
        self.headers = get_ua()
        
        if COOKIE:
            self.headers.update(COOKIE)
        
        if SOCKS5:
            ip, port = SOCKS5
            socks.set_default_proxy(socks.SOCKS5, ip, port)
            socket.socket = socks.socksocket
    
    def _verify(self, url):
        if not re.search('http:|https:', url):
            url = 'http://' + url
        return url
    
    def get(self, url):
        url = self._verify(url)
        try:
            r = self.session.get(url, timeout=self.timeout, headers=self.headers, verify=False, allow_redirects=False)
        except (requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout,
                requests.exceptions.Timeout,
                socket.timeout):
            pass
        return r
    
    def post(self, url, data):
        url = self._verify(url)
        try:
            r = self.session.post(url, data=data, timeout=self.timeout, headers=self.headers, verify=False,
                                  allow_redirects=False)
        except (requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout,
                requests.exceptions.Timeout,
                socket.timeout):
            pass
        return r
    
    def Req(self, url, method, data=None, headers=None):
        url = self._verify(url)
        try:
            if method == 'get':
                r = self.session.get(url, timeout=self.timeout, headers=headers, verify=False, allow_redirects=False)
            else:
                r = self.session.post(url, data=data, timeout=self.timeout, headers=headers, verify=False,
                                      allow_redirects=False)
        except (requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout,
                requests.exceptions.Timeout,
                socket.timeout):
            pass
        return r
