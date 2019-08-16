# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import concurrent.futures
import paramiko
import socket
from lib.verify import get_hosts
from lib.cli_output import console

vuln = ['SSH', '22']
user = ['root']


def SSHBruteforce(task):
    address, username, password = task.split('|')
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname=address, port=22, username=username, password=password, compress=True)
        result = 'IP: ' + address + ' SSH User: ' + username + ' Pass: ' + password
        console('BruteForce', address, result)
        return result
    except (
        paramiko.ssh_exception.AuthenticationException,
        paramiko.ssh_exception.SSHException,
        ConnectionResetError,
        socket.timeout,
        paramiko.ssh_exception.NoValidConnectionsError,
        EOFError):
        pass
    except Exception as e:
        pass


def ssh_check(ip):
    hosts = get_hosts(ip, user)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            task = {executor.submit(SSHBruteforce, i): i for i in hosts}
            for future in concurrent.futures.as_completed(task, timeout=10):
                result = future.result()
                if result:
                    return result
    except:
        pass
