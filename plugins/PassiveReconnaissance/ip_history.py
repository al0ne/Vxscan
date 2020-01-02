import re

from lib.Requests import Requests
from lib.iscdn import iscdn


def ipinfo(host):
    out = []
    if not re.search(r'\d+\.\d+\.\d+\.\d+', host):
        req = Requests()
        # noinspection PyBroadException
        try:
            r = req.get('https://viewdns.info/iphistory/?domain={}'.format(host))
            result = re.findall(r'(?<=<tr><td>)\d+\.\d+\.\d+\.\d+(?=</td><td>)', r.text, re.S | re.I)
            if result:
                for i in result:
                    if iscdn(i):
                        out.append(i)
        except Exception:
            pass

    return out
