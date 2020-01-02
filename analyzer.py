import ipaddress
import os
import re
from collections import Counter

from lib.bcolors import Bcolors
from lib.sqldb import Sqldb

dbname = 'result'

if os.path.exists('output.log'):
    os.remove('output.log')


def get_top(result):
    out = []
    count = Counter(result)
    L = sorted(count.items(), key=lambda item: item[1], reverse=True)
    L = L[:10]
    for i in L:
        app, appnum = i
        out.append('{}|{}'.format(app,appnum))
    return out


def get_cidr(iplist):
    cidrs = []
    for ip in iplist:
        cidr = re.sub(r'\d+$', '0/24', ip)
        cidrs.append(ipaddress.ip_network(cidr))

    result = []

    for cidr in cidrs:
        for i in iplist:
            ip = ipaddress.ip_address(i)
            if ip in cidr:
                result.append(str(cidr))
                break
    out = get_top(result)
    for i in out:
        cidr, num = i.split('|')
        print(cidr, num)


def query():
    print(Bcolors.RED + '网站数量:' + Bcolors.ENDC)
    sql = 'select count(*) from webinfo'
    _ = Sqldb(dbname).query(sql)
    print(_[0][0])
    sql = 'select service,count(service) as num from ports group by service order by num DESC'
    service = Sqldb(dbname).query(sql)
    print(Bcolors.RED + '服务统计:' + Bcolors.ENDC)
    for i in service:
        print(i[0], i[1])
    print(Bcolors.RED + 'Webinfo:' + Bcolors.ENDC)
    sql = 'select apps from webinfo where apps is not null'
    webinfo = Sqldb(dbname).query(sql)
    result = []
    for i in webinfo:
        result.extend(i[0].split(' , '))
    out = get_top(result)
    for j in out:
        cms,count = j.split('|')
        print(cms,count)
    print(Bcolors.RED + '端口统计:' + Bcolors.ENDC)
    sql = 'select port,count(port) as num from ports group by port order by num DESC limit 0,20'
    ports = Sqldb(dbname).query(sql)
    for i in ports:
        print(i[0], i[1])
    print(Bcolors.RED + 'C段统计:' + Bcolors.ENDC)
    cidrs = []
    sql = 'select ipaddr from webinfo order by ipaddr'
    cidr = Sqldb(dbname).query(sql)
    for i in cidr:
        cidrs.append(i[0])
    get_cidr(cidrs)
    print(Bcolors.RED + '可疑URL:' + Bcolors.ENDC)
    sql = "select domain,title,url,contype,rsp_len,rsp_code from urls where contype!='html' and contype !='vnd.microsoft.icon' and contype !='plain'"
    urls = Sqldb(dbname).query(sql)
    for i in urls:
        domain, title, url, contype, rsp_len, rsp_code = i
        if rsp_code == '200' and contype != 'None':
            print(domain, title, url, contype, rsp_len, rsp_code)
    print(Bcolors.RED + 'WAF:' + Bcolors.ENDC)
    sql = 'select waf,count(waf) as num from webinfo where waf is not NULL group by waf order by num DESC'
    waf = Sqldb(dbname).query(sql)
    for i in waf:
        print(i[0], i[1])
    print(Bcolors.RED + '地区分布:' + Bcolors.ENDC)
    sql = 'select address,count(address) as num from webinfo where address is not NULL group by address order by num DESC limit 0,20'
    country = Sqldb(dbname).query(sql)
    for i in country:
        print(i[0], i[1])


def gener():
    f = open('output.log', 'a', encoding='utf-8')
    webinfo = Sqldb(dbname).query('select domain,ipaddr,title,server,apps,waf,os from webinfo')
    for i in webinfo:
        domain, ipaddr, title, server, apps, waf, os = i
        print('\n' + '*' * 40 + ' ' + domain + ' ' + '*' * 40)
        f.write('\n' + '*' * 40 + ' ' + domain + ' ' + '*' * 40 + '\n')
        print('{}|{}|{}|{}|{}'.format(domain, ipaddr, title, server, waf))
        f.write('{}|{}|{}|{}|{}'.format(domain, ipaddr, title, server, waf) + '\n')
        print('指纹：' + str(apps))
        f.write('指纹：' + str(apps) + '\n')
        print('操作系统：' + str(os))
        f.write('操作系统：' + str(os) + '\n')
        ports = Sqldb(dbname).query(f"select ipaddr,service,port from ports where ipaddr = '{domain}'")
        for port in ports:
            domain, server, port = port
            print(domain, server, port)
            f.write('{}\t{}\t{}'.format(domain, server, port) + '\n')
        urls = Sqldb(dbname).query(f"select title,url,contype,rsp_len,rsp_code from urls where domain = '{domain}'")
        for url in urls:
            title, url, contype, rsp_len, rsp_code = url
            print('{}\t{}\t{}\t{}t{}'.format(title, url, contype, rsp_len, rsp_code))
            f.write('{}\t{}\t{}\t{}t{}'.format(title, url, contype, rsp_len, rsp_code) + '\n')
        vulns = Sqldb(dbname).query(f"select vuln from vuln where domain = '{ipaddr}'")
        for vuln in vulns:
            print(vuln[0])
            f.write(vuln[0] + '\n')


if __name__ == "__main__":
    query()
