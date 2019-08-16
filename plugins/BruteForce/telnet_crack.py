# coding=utf-8

import concurrent.futures
import telnetlib
from lib.cli_output import console
from lib.verify import get_hosts

vuln = ['telnet', '23']
user = ['root', 'admin']


def telnetBruteforce(task):
    address, username, password = task.split('|')
    try:
        telnet = telnetlib.Telnet(address, timeout=3)
        telnet.read_until("login: ")
        telnet.write(username + "\n")
        telnet.read_until("Password: ")
        telnet.write(password + "\n")
        telnet.close()
        result = 'IP: ' + address + ' Telnet User: ' + username + ' Pass: ' + password
        console('BruteForce', address, result)
        return result
    except:
        pass


def telnet_check(ip):
    hosts = get_hosts(ip, user)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            task = {executor.submit(telnetBruteforce, i): i for i in hosts}
            for future in concurrent.futures.as_completed(task, timeout=5):
                result = future.result()
                if result:
                    return result
    except:
        pass
