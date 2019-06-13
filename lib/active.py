# coding=utf-8
# author: al0ne
# https://github.com/al0ne
import socket
import concurrent.futures
from urllib import parse
import subprocess
import re
import platform


class ActiveCheck():
    def __init__(self, hosts):
        self.hosts = hosts
        self.out = []
        socket.setdefaulttimeout(1)

    def check(self, url):
        if ':' in url:
            loc = re.sub(r':\d+', '', url)
        else:
            loc = url
        try:
            if re.search('http|https', loc):
                loc = parse.urlparse(loc)
                result = socket.gethostbyname(loc.netloc)
            else:
                result = socket.gethostbyname(loc)
            if result:
                if platform.system() == 'Windows':
                    subprocess.check_output(['ping', '-n', '2', '-w', '1', result])
                else:
                    subprocess.check_output(['ping', '-c 2', '-W 1', result])
                if getattr(loc, 'netloc'):
                    self.out.append(url)
        except AttributeError:
            self.out.append(url)
        except Exception as e:
            pass

    def pool(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(self.check, self.hosts)
        return list(set(self.out))


if __name__ == "__main__":
    result = ActiveCheck(
        ['127.0.0.1']
    ).pool()
    print(result)
