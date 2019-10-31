from urllib import parse
import re
import dns.resolver


def parse_host(url):
    # 根据url得到主机host 例如 http://1.1.1.1:80 返回 1.1.1.1
    if (not parse.urlparse(url).path) and (parse.urlparse(url).path != '/'):
        host = url.replace('http://', '').replace('https://', '').rstrip('/')
    else:
        host = url.replace('http://', '').replace('https://', '').rstrip('/')
        host = re.sub(r'/\w+', '', host)
    if ':' in host:
        host = re.sub(r':\d+', '', host)
    return host


def parse_ip(host):
    host = parse_host(host)
    # 根据domain得到ip 例如www.xxx.com 得到 x.x.x.x
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1', '8.8.8.8']
        a = resolver.query(host, 'A')
        for i in a.response.answer:
            for j in i.items:
                if hasattr(j, 'address'):
                    if not re.search(r'1\.1\.1\.1|8\.8\.8\.8|127\.0\.0\.1|114\.114\.114\.114|0\.0\.0\.0', j.address):
                        return j.address
    except Exception as e:
        pass
    return host


def diff(urls):
    parms = []
    host = []
    result = []
    path = []
    # url = 'https://www.xxx.com/?page=1
    # 伪静态去重 通过urlparse取出来page=1,根据逗号拆分取出来k=page，然后保存不重复的k
    for i in urls:
        url = parse.urlparse(i)
        print(url)
        k, v, *_ = url.query.split('=')
        if url.netloc in host:
            if url.path in path:
                if k not in parms:
                    parms.append(k)
                    result.append(i)
            else:
                result.append(i)
                path.append(url.path)
        else:
            host.append(url.netloc)
            result.append(i)
            path.append(url.path)
            parms.append(k)

    return result


def dedup_link(urls):
    host = []
    _ = []
    furls = []
    for i in set(urls):
        # 只保留有参数的url其余的略过
        if '=' in i and not re.search(r"'|@|\+", i):
            # 　判断url是不是伪静态，伪静态与普通的去重方法不一样
            if re.search(r'/\?\d+=', i):
                furls.append(i)
            else:
                # 通过urlparse 对url进行去参去重，相同的丢弃
                url = parse.urlparse(i)
                if url.netloc + url.path not in host:
                    host.append(url.netloc + url.path)
                    _.append(i)
    _.extend(diff(furls))
    return _

