# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import requests
import json
import tldextract
import re
import sys
from lib.random_header import get_ua
from lib.iscdn import iscdn
from lib.bcolors import bcolors


def reverse_domain(host):
    # 查询旁站
    sys.stdout.write(bcolors.RED + "Reverse IP Domain Check：\n" + bcolors.ENDC)
    if iscdn(host):
        result = []
        data = {"remoteAddress": "{0}".format(host), "key": ""}
        header = get_ua()
        try:
            r = requests.post('https://domains.yougetsignal.com/domains.php', headers=header, data=data, timeout=5,
                              verify=False)
            text = json.loads(r.text)
            domain = tldextract.extract(host)
            for i in text.get('domainArray'):
                url = i[0]
                if url != host:
                    if tldextract.extract(url).domain == domain.domain:
                        result.append(url)
                    elif re.search(r'\d+\.\d+\.\d+\.\d+', url):
                        result.append(url)
        except:
            try:
                r = requests.get('http://api.hackertarget.com/reverseiplookup/?q={}'.format(host), headers=get_ua(),
                                 timeout=4, verify=False)
                if '<html>' not in r.text and 'No DNS A records found for' not in r.text:
                    text = r.text
                    for _ in text.split('\n'):
                        if _:
                            result.append(_)
                else:
                    result = []
            except:
                pass
        if len(result) < 20:
            if result:
                sys.stdout.write(bcolors.OKGREEN + "\n".join("[+] " + str(i) for i in result) + "\n" + bcolors.ENDC)
            else:
                sys.stdout.write(bcolors.OKGREEN + '[+] None' + "\n" + bcolors.ENDC)
            return result
        else:
            sys.stdout.write(bcolors.OKGREEN + 'The maximum number of domain names exceeded (20)' + bcolors.ENDC)
            return ['The maximum number of domain names exceeded (20)']
