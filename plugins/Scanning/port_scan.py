# coding:utf-8

# 参考了anthx大牛的脚本 https://raw.githubusercontent.com/AnthraX1/InsightScan/master/scanner.py

import socket
import re
import concurrent.futures
import sys
import os
import time
from urllib import parse
from lib.bcolors import bcolors
from lib.sqldb import Sqldb

sys.path.append(os.getcwd())

THREADNUM = 100  # 线程数

SIGNS = (
    # 协议 | 版本 | 关键字
    b'SMB|SMB|^\0\0\0.\xffSMBr\0\0\0\0.*',
    b'SMB|SMB|^\x83\x00\x00\x01\x8f',
    b"Xmpp|Xmpp|^\<\?xml version='1.0'\?\>",
    b'Netbios|Netbios|^\x79\x08.*BROWSE',
    b'Netbios|Netbios|^\x79\x08.\x00\x00\x00\x00',
    b'Netbios|Netbios|^\x05\x00\x0d\x03',
    b'Netbios|Netbios|^\x82\x00\x00\x00',
    b'Netbios|Netbios|\x83\x00\x00\x01\x8f',
    b'backdoor|backdoor|^500 Not Loged in',
    b'backdoor|backdoor|GET: command',
    b'backdoor|backdoor|sh: GET:',
    b'bachdoor|bachdoor|[a-z]*sh: .* command not found',
    b'backdoor|backdoor|^bash[$#]',
    b'backdoor|backdoor|^sh[$#]',
    b'backdoor|backdoor|^Microsoft Windows',
    b'DB2|DB2|.*SQLDB2RA',
    b'Finger|Finger|^\r\n	Line	  User',
    b'Finger|Finger|Line	 User',
    b'Finger|Finger|Login name: ',
    b'Finger|Finger|Login.*Name.*TTY.*Idle',
    b'Finger|Finger|^No one logged on',
    b'Finger|Finger|^\r\nWelcome',
    b'Finger|Finger|^finger:',
    b'Finger|Finger|^must provide username',
    b'Finger|Finger|finger: GET: ',
    b'FTP|FTP|^220.*\n331',
    b'FTP|FTP|^220.*\n530',
    b'FTP|FTP|^220.*FTP',
    b'FTP|FTP|^220 .* Microsoft .* FTP',
    b'FTP|FTP|^220 Inactivity timer',
    b'FTP|FTP|^220 .* UserGate',
    b'FTP|FTP|^220.*FileZilla Server',
    b'LDAP|LDAP|^\x30\x0c\x02\x01\x01\x61',
    b'LDAP|LDAP|^\x30\x32\x02\x01',
    b'LDAP|LDAP|^\x30\x33\x02\x01',
    b'LDAP|LDAP|^\x30\x38\x02\x01',
    b'LDAP|LDAP|^\x30\x84',
    b'LDAP|LDAP|^\x30\x45',
    b'RDP|RDP|^\x00\x01\x00.*?\r\n\r\n$',
    b'RDP|RDP|^\x03\x00\x00\x0b',
    b'RDP|RDP|^\x03\x00\x00\x11',
    b'RDP|RDP|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
    b'RDP|RDP|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
    b'RDP|RDP|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
    b'RDP|RDP|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
    b'RDP|RDP|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
    b'RDP|RDP|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
    b'RDP|RDP|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
    b'RDP-Proxy|RDP-Proxy|^nmproxy: Procotol byte is not 8\n$',
    b'Msrpc|Msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
    b'Msrpc|Msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
    b'Mssql|Mssql|^\x05\x6e\x00',
    b'Mssql|Mssql|^\x04\x01',
    b'Mssql|Mssql|;MSSQLSERVER;',
    b'Mysql|Mysql|mysql_native_password',
    b'Mysql|Mysql|^\x19\x00\x00\x00\x0a',
    b'Mysql|Mysql|^\x2c\x00\x00\x00\x0a',
    b'Mysql|Mysql|hhost \'',
    b'Mysql|Mysql|khost \'',
    b'Mysql|Mysql|mysqladmin',
    b'Mysql|Mysql|whost \'',
    b'Mysql|Mysql|^[.*]\x00\x00\x00\n.*?\x00',
    b'Mysql|Mysql|this MySQL server',
    b'Mysql|Mysql|MariaDB server',
    b'Mysql|Mysql|\x00\x00\x00\xffj\x04Host',
    b'db2jds|db2jds|^N\x00',
    b'Nagiosd|Nagiosd|Sorry, you \(.*are not among the allowed hosts...',
    b'Nessus|Nessus|< NTP 1.2 >\x0aUser:',
    b'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
    b'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
    b'oracle-dbSNMP|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
    b'oracle-https|^220- ora',
    b'RMI|RMI|\x00\x00\x00\x76\x49\x6e\x76\x61',
    b'RMI|RMI|^\x4e\x00\x09',
    b'PostgreSQL|PostgreSQL|Invalid packet length',
    b'PostgreSQL|PostgreSQL|^EFATAL',
    b'rpc-nfs|rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
    b'RPC|RPC|\x01\x86\xa0',
    b'RPC|RPC|\x03\x9b\x65\x42\x00\x00\x00\x01',
    b'RPC|RPC|^\x80\x00\x00',
    b'RSYNC|RSYNC|^@RSYNCD:',
    b'smux|smux|^\x41\x01\x02\x00',
    b'snmp-public|snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
    b'SNMP|SNMP|\x41\x01\x02',
    b'Socks|Socks|^\x05[\x00-\x08]\x00',
    b'SSL|SSL|^..\x04\0.\0\x02',
    b'SSL|SSL|^\x16\x03\x01..\x02...\x03\x01',
    b'SSL|SSL|^\x16\x03\0..\x02...\x03\0',
    b'SSL|SSL|SSL.*GET_CLIENT_HELLO',
    b'SSL|SSL|^-ERR .*tls_start_servertls',
    b'SSL|SSL|^\x16\x03\0\0J\x02\0\0F\x03\0',
    b'SSL|SSL|^\x16\x03\0..\x02\0\0F\x03\0',
    b'SSL|SSL|^\x15\x03\0\0\x02\x02\.*',
    b'SSL|SSL|^\x16\x03\x01..\x02...\x03\x01',
    b'SSL|SSL|^\x16\x03\0..\x02...\x03\0',
    b'Sybase|Sybase|^\x04\x01\x00',
    b'Telnet|Telnet|Telnet',
    b'Telnet|Telnet|^\xff[\xfa-\xff]',
    b'Telnet|Telnet|^\r\n%connection closed by remote host!\x00$',
    b'Rlogin|Rlogin|login: ',
    b'Rlogin|Rlogin|rlogind: ',
    b'Rlogin|Rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
    b'TFTP|TFTP|^\x00[\x03\x05]\x00',
    b'UUCP|UUCP|^login: password: ',
    b'VNC|VNC|^RFB',
    b'IMAP|IMAP|^\* OK.*?IMAP',
    b'POP|POP|^\+OK.*?',
    b'SMTP|SMTP|^220.*?SMTP',
    b'SMTP|SMTP|^554 SMTP',
    b'FTP|FTP|^220-',
    b'FTP|FTP|^220.*?FTP',
    b'FTP|FTP|^220.*?FileZilla',
    b'SSH|SSH|^SSH-',
    b'SSH|SSH|connection refused by remote host.',
    b'RTSP|RTSP|^RTSP/',
    b'SIP|SIP|^SIP/',
    b'NNTP|NNTP|^200 NNTP',
    b'SCCP|SCCP|^\x01\x00\x00\x00$',
    b'Webmin|Webmin|.*MiniServ',
    b'Webmin|Webmin|^0\.0\.0\.0:.*:[0-9]',
    b'websphere-javaw|websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a',
    b'Mongodb|Mongodb|MongoDB',
    b'Rsync|Rsync|@RSYNCD:',
    b'Squid|Squid|X-Squid-Error',
    b'Mssql|Mssql|MSSQLSERVER',
    b'Vmware|Vmware|VMware',
    b'ISCSI|ISCSI|\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'Redis|Redis|^-ERR unknown command',
    b'Redis|Redis|^-ERR wrong number of arguments',
    b'Redis|Redis|^-DENIED Redis is running',
    b'MemCache|MemCache|^ERROR\r\n',
    b'WebSocket|WebSocket|Server: WebSocket',
    b'HTTPS|HTTPS|Instead use the HTTPS scheme to access'
    b'HTTPS|HTTPS|HTTP request was sent to HTTPS',
    b'HTTPS|HTTPS|Location: https',
    b'SVN|SVN|^\( success \( 2 2 \( \) \( edit-pipeline svndiff1',
    b'Dubbo|Dubbo|^Unsupported command',
    b'HTTP|Elasticsearch|cluster_name.*elasticsearch',
    b'RabbitMQ|RabbitMQ|^AMQP\x00\x00\t\x01',
    b'HTTP|HTTP|HTTP/1.1'

)


def get_server(port):
    SERVER = {
        'FTP': '21',
        'SSH': '22',
        'Telnet': '23',
        'SMTP': '25',
        'DNS': '53',
        'DHCP': '68',
        'HTTP': '80',
        'TFTP': '69',
        'HTTP': '8080',
        'POP3': '995',
        'NetBIOS': '139',
        'IMAP': '143',
        'HTTPS': '443',
        'SNMP': '161',
        'LDAP': '489',
        'SMB': '445',
        'SMTPS': '465',
        'Linux R RPE': '512',
        'Linux R RLT': '513',
        'Linux R cmd': '514',
        'Rsync': '873',
        'IMAPS': '993',
        'Proxy': '1080',
        'JavaRMI': '1099',
        'Lotus': '1352',
        'MSSQL': '1433',
        'MSSQL Monitor': '1434',
        'Oracle': '1521',
        'PPTP': '1723',
        'cPanel': '2082',
        'CPanel': '2083',
        'Zookeeper': '2181',
        'Docker': '2375',
        'Zebra': '2604',
        'MySQL': '3306',
        'Kangle': '3312',
        'RDP': '3389',
        'SVN': '3690',
        'Rundeck': '4440',
        'GlassFish': '4848',
        'PostgreSql': '5432',
        'PcAnywhere': '5632',
        'VNC': '5900',
        'CouchDB': '5984',
        'varnish': '6082',
        'Redis': '6379',
        'Weblogic': '9001',
        'Kloxo': '7778',
        'Zabbix': '8069',
        'RouterOS': '8291',
        'WebSphere': '9090',
        'Elasticsearch': '9200',
        'Elasticsearch': '9300',
        'Zabbix': '10050',
        'Zabbix': '10051',
        'Memcached': '11211',
        'MongoDB': '27017',
        'MongoDB': '28017',
        'Hadoop': '50070'
    }
    for k, v in SERVER.items():
        if v == port:
            return '{}:{}'.format(k, port)
    return 'Unknown:{}'.format(port)


PORTS = [21, 22, 23, 25, 26, 37, 47, 49, 53, 69, 70, 79, 80, 81, 82, 83, 84, 88, 89, 110, 111, 119, 123, 129, 135,
         137, 139, 143, 161, 175, 179, 195, 311, 389, 443, 444, 445, 465, 500, 502, 503, 512, 513, 514, 515, 520,
         523, 530, 548, 554, 563, 587, 593, 623, 626, 631, 636, 660, 666, 749, 751, 771, 789, 873, 901, 902, 990,
         992, 993, 995, 1000, 1010, 1023, 1024, 1025, 1080, 1088, 1099, 1111, 1177, 1200, 1234, 1311, 1325, 1352,
         1400, 1433, 1434, 1471, 1515, 1521, 1599, 1604, 1723, 1741, 1777, 1883, 1900, 1911, 1920, 1962, 1991,
         2000, 2049, 2067, 2081, 2082, 2083, 2086, 2087, 2121, 2123, 2152, 2181, 2222, 2323, 2332, 2333, 2375,
         2376, 2379, 2404, 2433, 2455, 2480, 2601, 2604, 2628, 3000, 3001, 3128, 3260, 3269, 3283, 3299, 3306,
         3307, 3310, 3311, 3312, 3333, 3386, 3388, 3389, 3460, 3478, 3493, 3541, 3542, 3560, 3661, 3689, 3690,
         3702,
         3749, 3794, 3780, 3784, 3790, 4000, 4022, 4040, 4063, 4064, 4070, 4200, 4343, 4369, 4400, 4440, 4443,
         4444,
         4500, 4550, 4567, 4664, 4730, 4782, 4786, 4800, 4840, 4848, 4899, 4911, 4949, 5000, 5001, 5006, 5007,
         5008,
         5009, 5060, 5094, 5222, 5269, 5353, 5357, 5431, 5432, 5433, 5555, 5560, 5577, 5601, 5631, 5632, 5666,
         5672,
         5683, 5800, 5801, 5858, 5900, 5901, 5938, 5984, 5985, 5986, 6000, 6001, 6014, 6082, 6379, 6390, 6664,
         6666, 6667, 6881, 6969, 7000, 7001, 7002, 7071, 7080, 7218, 7474, 7547, 7548, 7549, 7657, 7777, 7779,
         7903,
         7905, 8000, 8001, 8008, 8009, 8010, 8060, 8069, 8080, 8081, 8082, 8083, 8086, 8087, 8088, 8089, 8090,
         8098,
         8099, 8112, 8126, 8139, 8140, 8161, 8181, 8191, 8200, 8291, 8307, 8333, 8334, 8443, 8554, 8649, 8688,
         8800, 8834, 8880, 8883, 8888, 8889, 8899, 9000, 9001, 9002, 9009, 9014, 9042, 9043, 9050, 9051, 9080,
         9081, 9090, 9092, 9100, 9151, 9160, 9191, 9200, 9300, 9306, 9418, 9443, 9595, 9600, 9869, 9903, 9943,
         9944, 9981, 9990, 9998, 9999, 10000, 10001, 10050, 10051, 10243, 10554, 11211, 11300, 12345, 13579, 14147,
         16010, 16992, 16993, 17000, 17778, 18081, 18245, 18505, 20000, 20547, 21025, 21379, 21546, 22022, 22222,
         23023, 23389, 23424, 25105, 25565, 27015, 27016, 27017, 27018, 27019, 28015, 28017, 28561, 30000, 30718,
         32400,
         32764, 32768, 32769, 32770, 32771, 33389, 33890, 33899, 37777, 38190, 40001, 40049, 40650, 41706, 42178,
         43382, 44818, 47808, 48899, 49152, 49153, 50000, 50010, 50011, 50015, 50030, 50050, 50060, 50070, 50100,
         51106, 53413, 54138, 55443, 55553, 55554, 62078, 64738, 65535]

PROBE = {
    'GET / HTTP/1.0\r\n\r\n'
}


class ScanPort():
    def __init__(self, ipaddr):
        self.ipaddr = ipaddr
        self.port = []
        self.out = []
        self.num = 0
    
    def socket_scan(self, hosts):
        global PROBE
        socket.setdefaulttimeout(1)
        ip, port = hosts.split(':')
        try:
            if len(self.port) < 25:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((ip, int(port)))
                if result == 0:
                    self.port.append(port)
                    for i in PROBE:
                        sock.sendall(i.encode())
                        response = sock.recv(256)
                        sock.close()
                        if response:
                            break
                    if response:
                        for pattern in SIGNS:
                            pattern = pattern.split(b'|')
                            if re.search(pattern[-1], response, re.IGNORECASE):
                                proto = '{}:{}'.format(pattern[1].decode(), port)
                                self.out.append(proto)
                                break
            else:
                self.num = 1
        
        except (socket.timeout, ConnectionResetError):
            pass
        except:
            pass
    
    def save(self, ipaddr, result):
        Sqldb('result').get_ports(ipaddr, result)
    
    def run(self, ip):
        hosts = []
        global PORTS, THREADNUM
        for i in PORTS:
            hosts.append('{}:{}'.format(ip, i))
        try:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=THREADNUM) as executor:
                result = {executor.submit(self.socket_scan, i): i for i in hosts}
                for future in concurrent.futures.as_completed(result):
                    future.result()
        except EOFError:
            pass
    
    def pool(self):
        sys.stdout.write(bcolors.RED + "PortScan：\n" + bcolors.ENDC)
        out = []
        try:
            # 判断给出的url是www.baiud.com还是www.baidu.com/path这种形式
            if (not parse.urlparse(self.ipaddr).path) and (parse.urlparse(self.ipaddr).path != '/'):
                self.ipaddr = self.ipaddr.replace('http://', '').replace('https://', '').rstrip('/')
            else:
                self.ipaddr = self.ipaddr.replace('http://', '').replace('https://', '').rstrip('/')
                self.ipaddr = re.sub('/\w+', '', self.ipaddr)
            if re.search('\d+\.\d+\.\d+\.\d+', self.ipaddr):
                ipaddr = self.ipaddr
            else:
                ipaddr = socket.gethostbyname(self.ipaddr)
            if ':' in ipaddr:
                ipaddr = re.sub(':\d+', '', ipaddr)
            self.run(ipaddr)
        except Exception as e:
            pass
        for i in self.out:
            _, port = i.split(':')
            out.append(port)
        for i in self.port:
            if i not in out:
                self.out.append(get_server(i))
        if self.num == 0:
            ports = list(set(self.out))
            self.save(self.ipaddr, ports)
            for _ in ports:
                sys.stdout.write(bcolors.OKGREEN + '[+] {}\n'.format(_) + bcolors.ENDC)
            return list(set(self.out))
        else:
            self.save(self.ipaddr, ['Portspoof:0'])
            sys.stdout.write(bcolors.OKGREEN + '[+] Portspoof:0\n' + bcolors.ENDC)
            return ['Portspoof:0']


if __name__ == "__main__":
    start_time = time.time()
    ScanPort('127.0.0.1').pool()
    end_time = time.time()
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
