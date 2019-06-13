# coding = utf-8

import re
import json
from lib.pyh import *


def save_html(result, name):
    page = PyH('REPORT')
    page.addCSS(
        'https://cdn.bootcss.com/bootstrap/3.3.7/css/bootstrap.css')  # 第二步：需要加载我们要使用的Bootstrap模板css文件，需要的话还可以加载js
    Container = page << body(id='Body', cl='bg-warning') << div(id="container",
                                                                cl="container")  # 第三步：通过移位符“<<”，来生成所属标签；“<<”左侧最终必须是page

    # 报告标题 start
    Headrow = Container << div(id="Headrow", cl="row")
    Headrow << h1(id="HeadH1", align="center") << strong("Vxscan run result ", id="HeadTxt")
    Headrow << br()
    # 报告标题 end

    # 测试用例 start
    Cases = Container << div(cl="row")
    # --一个测试用例-- start
    Case1 = Cases << div(cl="col-xs-12 col-md-12") << table(cl="table table-striped")
    # --一个列表--
    thead1 = ["Host", "Title", "WAF", "WEBINFO", "Server", "PORTS", "URLS", "Vuln"]
    Case1Thead1 = Case1 << thead()
    Case1Thead1 << tr() << th(thead1[0]) + th(thead1[1]) + th(thead1[2]) + th(thead1[3]) + th(thead1[4]) + th(
        thead1[5]) + th(thead1[6]) + th(thead1[7])
    for i in result:
        result = []
        for k, v in i.items():
            host = k
            for k1, v1 in v.items():
                ports = v.get('Ports')
                vuln = v.get('Vuln')
                if v.get('Webinfo') != None:
                    waf = v.get('WAF')
                    title = v.get('Webinfo').get('title')
                    apps = v.get('Webinfo').get('apps')
                    server = v.get('Webinfo').get('server')
                    urls = v.get('URLS')
        if title == None:
            title = ''
        if server == None:
            server = ''
        if urls:
            for _ in urls:
                # url = '{}\t{}\t{}\t{}\t{}'.format(_.get('title'), _.get('url'), _.get('contype'), _.get('rsp_len'),
                #                                   _.get('rsp_code'))
                if _.get('title') == 'None':
                    url = '<a href=http://{}{}>{}</a>'.format(host, _.get('url'), _.get('url'))
                else:
                    url = '<a href=http://{}{}>{}</a>'.format(host, _.get('url'), _.get('title'))
                result.append(url)
            result = ','.join(result)
            result = re.sub(',', '</br>', result)
        else:
            result = ''
        ports = ','.join(ports)
        ports = re.sub(',', '</br>', ports)
        vuln = ','.join(vuln)
        vuln = re.sub(',', '</br>', vuln)
        if waf == {}:
            waf = ''
        if apps:
            apps = ','.join(apps)
            apps = re.sub(',', '</br>', apps)
        else:
            apps = ''
        host = '<a href=http://' + host + '>' + host + '</a>'
        tbody1 = [host, title, waf, apps, server, ports, result, vuln]
        Case1Tbody1 = Case1 << tbody()
        Case1Tbody1 << tr() << th(tbody1[0]) + td(tbody1[1]) + td(tbody1[2]) + td(tbody1[3]) + td(tbody1[4]) + td(
            tbody1[5]) + td(tbody1[6]) + td(tbody1[7])
    page.printOut('report/{}.html'.format(name))


if __name__ == "__main__":
    with open("../report/result.json", 'rb') as f:
        result = json.load(f)
        save_html(result, 'test')
