import re
from lib.Requests import Requests
from lib.waf import WAF_RULE

payload = (
    "/index.php?id=1 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(XSS)</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')",
    "/../../../etc/passwd",
    "/.git/")


def verify(headers, content):
    for i in WAF_RULE:
        name, method, position, regex = i.split('|')
        if method == 'headers':
            if headers.get(position) != None:
                if re.search(regex, str(headers.get(position))) != None:
                    return name
        else:
            if re.search(regex, str(content)):
                return name
    return 'NoWAF'


def checkwaf(url):
    try:
        req = Requests()
        r = req.get(url)
        result = verify(r.headers, r.text[:10000])
        if result == 'NoWAF':
            for i in payload:
                r = req.get(url + i)
                result = verify(r.headers, r.text[:10000])
        return result
    except:
        return 'NoWAF'
