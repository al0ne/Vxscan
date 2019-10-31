# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import requests
import json
import tldextract
import re
from lib.cli_output import console
from lib.random_header import get_ua
from lib.iscdn import iscdn


def reverse_domain(host):
    # 查询旁站
    # sys.stdout.write(Bcolors.RED + "\nReverse IP Domain Check：\n" + Bcolors.ENDC)
    if iscdn(host):
        result = []
        data = {"remoteAddress": "{0}".format(host), "key": ""}
        header = get_ua()
        try:
            r = requests.post('https://domains.yougetsignal.com/domains.php',
                              headers=header,
                              data=data,
                              timeout=5,
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
                r = requests.get('http://api.hackertarget.com/reverseiplookup/?q={}'.format(host),
                                 headers=get_ua(),
                                 timeout=4,
                                 verify=False)
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
                for i in result:
                    console('reverse_domain', host, i + '\n')
            else:
                console('reverse_domain', host, 'None\n')
            return result
        else:
            console('reverse_domain', host, 'The maximum number of domain names exceeded (20)\n')
            # sys.stdout.write(Bcolors.OKGREEN + 'The maximum number of domain names exceeded (20)\n' + Bcolors.ENDC)
            return ['The maximum number of domain names exceeded (20)']
