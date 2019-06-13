import requests
from lib.verify import get_list
from lib.random_header import HEADERS

vuln = ['Jenkins']


def jenkins(url):
    try:
        payload = "/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition/checkScriptCompile"
        r = requests.get(url + payload, timeout=5, headers=HEADERS)
        if 'java.lang.NullPointerException' in r.text:
            return "CVE-2018-1000861 Jenkins_rce url: {}".format(url)
    except Exception as e:
        print(e)


def check(ip, ports, apps):
    try:
        probe = get_list(ip, ports)
        for url in probe:
            r = requests.get(url, timeout=3, headers=HEADERS)
            if 'Jenkins' in r.text:
                result = jenkins(url)
    except Exception as e:
        pass
    if result:
        return result
