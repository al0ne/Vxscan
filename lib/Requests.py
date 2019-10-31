# coding=utf-8

import OpenSSL
import requests
import urllib3
import logging
import hashlib
import random
import re
import ssl
import socks
import socket
from lib.random_header import get_ua
from lib.settings import TIMEOUT, COOKIE, SOCKS5


def verify(url):
    if not re.search('http:|https:', url):
        url = 'http://' + url
    return url


class Requests:
    def __init__(self):
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings()

        self.timeout = TIMEOUT
        self.session = requests.Session()
        self.headers = get_ua()

        if COOKIE == 'random':
            plain = ''.join([random.choice('0123456789') for _ in range(8)])
            md5sum = hashlib.md5()
            md5sum.update(plain.encode('utf-8'))
            md5 = md5sum.hexdigest()
            self.headers.update({'Cookie': 'SESSION=' + md5})
        else:
            self.headers.update(COOKIE)

        if SOCKS5:
            ip, port = SOCKS5
            socks.set_default_proxy(socks.SOCKS5, ip, port)
            socket.socket = socks.socksocket

    def scan(self, url):
        url = verify(url)
        try:
            r = self.session.get(url,
                                 timeout=self.timeout,
                                 headers=self.headers,
                                 verify=False,
                                 stream=True,
                                 allow_redirects=False)
            return r

        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout,
                requests.exceptions.SSLError, requests.exceptions.ConnectionError, ssl.SSLError, AttributeError,
                ConnectionRefusedError, socket.timeout, urllib3.exceptions.ReadTimeoutError, OpenSSL.SSL.WantReadError):
            pass
        except Exception as e:
            logging.exception(e)

    def get(self, url):
        url = verify(url)
        try:
            r = self.session.get(url, timeout=self.timeout, headers=self.headers, verify=False, allow_redirects=False)
            return r
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout,
                requests.exceptions.SSLError, requests.exceptions.ConnectionError, ssl.SSLError, AttributeError,
                ConnectionRefusedError, socket.timeout, urllib3.exceptions.ReadTimeoutError, OpenSSL.SSL.WantReadError):
            pass
        except Exception as e:
            logging.exception(e)

    def post(self, url, data):
        url = verify(url)
        try:
            r = self.session.post(url,
                                  data=data,
                                  timeout=self.timeout,
                                  headers=self.headers,
                                  verify=False,
                                  allow_redirects=False)
            return r
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout,
                requests.exceptions.SSLError, requests.exceptions.ConnectionError, ssl.SSLError, AttributeError,
                ConnectionRefusedError, socket.timeout, urllib3.exceptions.ReadTimeoutError, OpenSSL.SSL.WantReadError):
            pass
        except Exception as e:
            logging.exception(e)

    def request(self, url, method, data=None, headers=None):
        url = verify(url)
        try:
            if method == 'get':
                r = self.session.get(url, timeout=self.timeout, headers=headers, verify=False, allow_redirects=True)
                return r
            else:
                r = self.session.post(url,
                                      data=data,
                                      timeout=self.timeout,
                                      headers=headers,
                                      verify=False,
                                      allow_redirects=False)
                return r
        except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.Timeout,
                requests.exceptions.SSLError, requests.exceptions.ConnectionError, ssl.SSLError, AttributeError,
                ConnectionRefusedError, socket.timeout, urllib3.exceptions.ReadTimeoutError, OpenSSL.SSL.WantReadError):
            pass
        except Exception as e:
            logging.exception(e)
