# author: al0ne
# https://github.com/al0ne

import concurrent.futures
import pymysql
from lib.verify import get_hosts
from lib.cli_output import console

vuln = ['mysql', '3306']
user = ['root']


def mysqlBruteforce(task):
    address, username, password = task.split('|')
    try:
        db = pymysql.connect(address, username, password, "mysql", connect_timeout=5)
        result = 'IP: ' + address + ' Mysql User: ' + username + ' Pass: ' + password
        console('BruteForce', address, result + '\n')
        return result
    except Exception as e:
        pass


def mysql_check(ip):
    hosts = get_hosts(ip, user)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            task = {executor.submit(mysqlBruteforce, i): i for i in hosts}
            for future in concurrent.futures.as_completed(task, timeout=5):
                result = future.result()
                if result:
                    return result
    except:
        pass
