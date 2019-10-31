import re
from lib.verify import get_list
from lib.Requests import Requests


def get_info(url):
    try:
        req = Requests()
        url = url + '/solr/'
        r = req.get(url)
        if r.status_code is 200 and 'Solr Admin' in r.text and 'Dashboard' in r.text:
            return 'Apache Solr Admin leask: ' + url
    except Exception:
        pass


def check(url, ip, ports, apps):
    result = []
    probe = get_list(url, ports)
    for i in probe:
        if re.search(r':\d+', i):
            out = get_info(i)
            if out:
                result.append(out)
    if result:
        return result
