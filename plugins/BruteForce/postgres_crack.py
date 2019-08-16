# coding=utf-8
import concurrent.futures
import psycopg2
from lib.verify import get_hosts
from lib.cli_output import console

vuln = ['postgresql', '5432']
user = ['postgres']


def psqlBruteforce(task):
    address, username, password = task.split('|')
    try:
        conn = psycopg2.connect(host=address, port=5432, user=username, password=password)
        result = 'IP: ' + address + ' Postgresql User: ' + username + ' Pass: ' + password
        console('BruteForce', address, result)
        return result
    except Exception as e:
        pass


def postgres_check(ip):
    hosts = get_hosts(ip, user)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            task = {executor.submit(psqlBruteforce, i): i for i in hosts}
            for future in concurrent.futures.as_completed(task, timeout=3):
                result = future.result()
                if result:
                    return result
    except:
        pass
