# coding=utf-8
from lib.verify import verify
from plugins.BruteForce.mysql_crack import mysql_check
from plugins.BruteForce.postgres_crack import postgres_check
from plugins.BruteForce.ssh_crack import ssh_check

class Crack():
    def __init__(self):
        self.result = []
    
    def pool(self, ip, ports):
        if verify(['3306', 'mysql'], ports, ['']):
            result = mysql_check(ip)
            if result:
                self.result.append(result)
        if verify(['22', 'SSH'], ports, ['']):
            result = ssh_check(ip)
            if result:
                self.result.append(result)
        if verify(['5432', 'PostgreSQL'], ports, ['']):
            result = postgres_check(ip)
            if result:
                self.result.append(result)
        return self.result
