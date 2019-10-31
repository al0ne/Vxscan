# coding:utf-8

# 参考了anthx大牛的脚本 https://raw.githubusercontent.com/AnthraX1/InsightScan/master/scanner.py

import socket
import re
import concurrent.futures
import sys
import os
import time
import logging
import random
from urllib import parse
from lib.cli_output import console
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
    b'HTTPS|HTTPS|HTTP request to an HTTPS server',
    b'HTTPS|HTTPS|Location: https',
    b'SVN|SVN|^\( success \( 2 2 \( \) \( edit-pipeline svndiff1',
    b'Dubbo|Dubbo|^Unsupported command',
    b'HTTP|Elasticsearch|cluster_name.*elasticsearch',
    b'RabbitMQ|RabbitMQ|^AMQP\x00\x00\t\x01',
    b'HTTP|HTTP|HTTP/1.1',
    b'HTTP|HTTP|HTTP/1.0',
    b'Zookeeper|Zookeeper|^Zookeeper version: ')


def get_server(port):
    SERVER = {
        '21': 'FTP',
        '22': 'SSH',
        '23': 'Telnet',
        '25': 'SMTP',
        '53': 'DNS',
        '68': 'DHCP',
        '8080': 'HTTP',
        '69': 'TFTP',
        '995': 'POP3',
        '135': 'RPC',
        '139': 'NetBIOS',
        '143': 'IMAP',
        '443': 'HTTPS',
        '161': 'SNMP',
        '489': 'LDAP',
        '445': 'SMB',
        '465': 'SMTPS',
        '512': 'Linux R RPE',
        '513': 'Linux R RLT',
        '514': 'Linux R cmd',
        '873': 'Rsync',
        '993': 'IMAPS',
        '1080': 'Proxy',
        '1099': 'JavaRMI',
        '1352': 'Lotus',
        '1433': 'MSSQL',
        '1521': 'Oracle',
        '1723': 'PPTP',
        '2082': 'cPanel',
        '2083': 'CPanel',
        '2181': 'Zookeeper',
        '2222': 'DircetAdmin',
        '2375': 'Docker',
        '2604': 'Zebra',
        '3306': 'MySQL',
        '3312': 'Kangle',
        '3389': 'RDP',
        '3690': 'SVN',
        '4440': 'Rundeck',
        '4848': 'GlassFish',
        '5432': 'PostgreSql',
        '5632': 'PcAnywhere',
        '5900': 'VNC',
        '5984': 'CouchDB',
        '6082': 'varnish',
        '6379': 'Redis',
        '9001': 'Weblogic',
        '7778': 'Kloxo',
        '10051': 'Zabbix',
        '8291': 'RouterOS',
        '9300': 'Elasticsearch',
        '11211': 'Memcached',
        '28017': 'MongoDB',
        '50070': 'Hadoop'
    }

    for k, v in SERVER.items():
        if k == port:
            return v
    return 'Unknown'


PORTS = [
    21, 22, 23, 25, 26, 37, 47, 49, 53, 69, 70, 79, 80, 81, 82, 83, 84, 88, 89, 110, 111, 119, 123, 129, 135, 137, 139,
    143, 146, 161, 163, 175, 179, 195, 199, 222, 258, 259, 264, 280, 301, 306, 311, 340, 366, 389, 425, 427, 443, 444,
    445, 458, 465, 481, 497, 500, 502, 503, 512, 513, 514, 515, 520, 523, 524, 530, 541, 548, 554, 555, 726, 749, 751,
    765, 771, 777, 783, 787, 789, 808, 843, 873, 880, 888, 898, 901, 902, 981, 987, 990, 992, 993, 995, 996, 999, 1000,
    1007, 1010, 1021, 1023, 1024, 1025, 1080, 1088, 1099, 1102, 1111, 1117, 1119, 1126, 1141, 1325, 1328, 1334, 1352,
    1400, 1417, 1433, 1434, 1443, 1455, 1461, 1471, 1494, 1503, 1515, 1521, 1524, 1533, 2179, 2181, 2196, 2200, 2222,
    2251, 2260, 2288, 2301, 2323, 2332, 2333, 2366, 2375, 2376, 2379, 2399, 2401, 2404, 2433, 2455, 2480, 2492, 2500,
    2522, 2525, 2557, 2601, 2604, 2628, 2638, 2710, 2725, 2800, 2809, 2811, 2869, 2875, 2920, 2998, 3000, 3001, 3003,
    3011, 3013, 3017, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3269, 3283, 3299, 3306, 3307, 3310, 3311, 3312,
    3333, 3351, 3367, 3386, 3388, 3389, 3404, 3460, 3476, 3478, 3493, 3517, 3527, 3541, 3542, 3546, 3551, 3560, 3580,
    3659, 3661, 3689, 3690, 3702, 3703, 3737, 3749, 3766, 3780, 3784, 3790, 3794, 3809, 3814, 3851, 3869, 3871, 3878,
    3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4022, 4040, 4045, 4063, 4064, 4070, 4111,
    4129, 4200, 4224, 4242, 4279, 4321, 4343, 5432, 5550, 5555, 5560, 5566, 5577, 5601, 5631, 5632, 5633, 5666, 5672,
    5683, 5718, 5730, 5800, 5801, 5815, 5822, 5825, 5850, 5858, 5859, 5862, 5877, 5900, 5901, 5915, 5922, 5925, 5938,
    5950, 5952, 5984, 5985, 5986, 6000, 7001, 7002, 7004, 7007, 7019, 7025, 7070, 7071, 7080, 7100, 7103, 7106, 7218,
    7402, 7435, 7443, 7474, 7496, 7512, 7547, 7548, 7549, 7625, 7627, 7657, 7676, 7741, 7777, 7779, 7800, 7903, 7905,
    7911, 8000, 8001, 8008, 8009, 8010, 8031, 8042, 8045, 8060, 8069, 8080, 8081, 8082, 8083, 8086, 8087, 8088, 8089,
    8090, 8091, 8093, 8098, 8099, 8112, 8126, 8139, 8140, 8161, 8181, 8191, 8200, 8222, 8254, 8291, 8300, 8307, 8333,
    8334, 8383, 8390, 8400, 8402, 8433, 8443, 8500, 8554, 8600, 8649, 8654, 8688, 8701, 8800, 8834, 8873, 8880, 8883,
    8888, 8889, 8899, 9151, 9160, 9191, 9200, 9207, 9220, 9290, 9300, 9306, 9415, 9418, 9443, 9485, 9500, 9535, 9575,
    9595, 9600, 9618, 9666, 9869, 9898, 9900, 9903, 9917, 9929, 9943, 9944, 9968, 9981, 9990, 9998, 9999, 10000, 10001,
    10012, 10050, 10051, 10082, 10180, 10215, 10243, 10554, 10566, 10621, 10626, 10778, 11211, 11300, 11967, 12000,
    12124, 12174, 12265, 12345, 12888, 13456, 13579, 13722, 14000, 14003, 14147, 14238, 15000, 15660, 15742, 16010,
    16012, 21571, 22022, 22222, 22939, 23023, 23307, 23389, 23424, 23502, 24212, 24444, 24800, 25105, 25565, 26214,
    27000, 27015, 27016, 27017, 27018, 27019, 27545, 27715, 28015, 28017, 28201, 28561, 30000, 30718, 30951, 31038,
    31337
]

PROBE = {'GET / HTTP/1.0\r\n\r\n'}


class ScanPort:
    def __init__(self, ipaddr, dbname):
        self.ipaddr = ipaddr
        self.port = []
        self.dbname = dbname
        self.out = []
        self.num = 0

    def regex(self, response, port):
        match = False

        if re.search(b'<title>502 Bad Gateway', response):
            return match

        for pattern in SIGNS:
            pattern = pattern.split(b'|')
            if re.search(pattern[-1], response, re.IGNORECASE):
                text = response.decode('utf-8', 'ignore')
                match = True
                proto = {"server": pattern[1].decode(), "port": port, "banner": text}
                self.out.append(proto)
                break
        if not match:
            proto = {"server": get_server(port), "port": port, "banner": response.decode('utf-8', 'ignore')}
            self.out.append(proto)

    def socket_scan(self, hosts):
        global PROBE
        response = ''
        socket.setdefaulttimeout(2)
        ip, port = hosts.split(':')
        try:
            if len(self.port) < 30:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((ip, int(port)))
                # 建立3次握手成功
                if result == 0:
                    try:
                        for i in PROBE:
                            sock.sendall(i.encode())
                            response = sock.recv(512)
                            sock.close()
                            # 发送payload 获取响应 来判断服务
                            if response:
                                self.regex(response, port)
                            else:
                                proto = {"server": get_server(port), "port": port, "banner": ''}
                                self.out.append(proto)
                            break
                    except socket.timeout:
                        proto = {"server": get_server(port), "port": port, "banner": ''}
                        self.out.append(proto)

                    self.port.append(port)

            else:
                self.num = 1

        except (socket.timeout, ConnectionResetError, OSError):
            pass
        except Exception as e:
            # traceback.print_exc(e)
            logging.exception(e)

    def save(self, ipaddr, result):
        Sqldb(self.dbname).get_ports(ipaddr, result)

    def run(self, ip):
        hosts = []
        global PORTS, THREADNUM
        random.shuffle(PORTS)
        for i in PORTS:
            hosts.append('{}:{}'.format(ip, i))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=THREADNUM) as executor:
                result = {executor.submit(self.socket_scan, i): i for i in hosts}
                for future in concurrent.futures.as_completed(result, timeout=3):
                    future.result()
                    if self.num == 1:
                        break
        except (EOFError, concurrent.futures._base.TimeoutError):
            pass

    def pool(self):
        out = []
        try:
            # 判断给出的url是www.baiud.com还是www.baidu.com/path这种形式
            if (not parse.urlparse(self.ipaddr).path) and (parse.urlparse(self.ipaddr).path != '/'):
                self.ipaddr = self.ipaddr.replace('http://', '').replace('https://', '').rstrip('/')
            else:
                self.ipaddr = self.ipaddr.replace('http://', '').replace('https://', '').rstrip('/')
                self.ipaddr = re.sub(r'/\w+', '', self.ipaddr)
            if re.search(r'\d+\.\d+\.\d+\.\d+', self.ipaddr):
                ipaddr = self.ipaddr
            else:
                ipaddr = socket.gethostbyname(self.ipaddr)
            if ':' in ipaddr:
                ipaddr = re.sub(r':\d+', '', ipaddr)
            self.run(ipaddr)
        except Exception as e:
            pass

        if self.num == 0:
            self.save(self.ipaddr, self.out)
            for _ in self.out:
                out.append('{}:{}'.format(_.get('server'), _.get('port')))
                console('PortScan', self.ipaddr, '{}:{}\n'.format(_.get('server'), _.get('port')))
            return out
        else:
            self.save(self.ipaddr, [{"server": 'Portspoof', "port": '0', "banner": ''}])
            console('PortScan', self.ipaddr, 'Portspoof:0\n')
            return ['Portspoof:0']


if __name__ == "__main__":
    start_time = time.time()
    ScanPort('127.0.0.1', 'result').pool()
    # print(len(PORTS))
    end_time = time.time()
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
