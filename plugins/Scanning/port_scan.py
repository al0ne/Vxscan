# coding:utf-8

# 参考了anthx大牛的脚本 https://raw.githubusercontent.com/AnthraX1/InsightScan/master/scanner.py

import concurrent.futures
import logging
import random
import re
import socket
import time
from urllib import parse

from lib.cli_output import console
from lib.sqldb import Sqldb

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
    b'MySQL|MySQL|mysql_native_password',
    b'MySQL|MySQL|^\x19\x00\x00\x00\x0a',
    b'MySQL|MySQL|^\x2c\x00\x00\x00\x0a',
    b'MySQL|MySQL|hhost \'',
    b'MySQL|MySQL|khost \'',
    b'MySQL|MySQL|mysqladmin',
    b'MySQL|MySQL|whost \'',
    b'MySQL|MySQL|^[.*]\x00\x00\x00\n.*?\x00',
    b'MySQL|MySQL|this MySQL server',
    b'MySQL|MySQL|MariaDB server',
    b'MySQL|MySQL|\x00\x00\x00\xffj\x04Host',
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
    b'Rsync|Rsync|^@RSYNCD:',
    b'Rsync|Rsync|@RSYNCD:',
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
    b'Kangle|Kangle|HTTP.*kangle',
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
    b'Squid|Squid|X-Squid-Error',
    b'Mssql|Mssql|MSSQLSERVER',
    b'Vmware|Vmware|VMware',
    b'ISCSI|ISCSI|\x00\x02\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    b'Redis|Redis|^-ERR unknown command',
    b'Redis|Redis|^-ERR wrong number of arguments',
    b'Redis|Redis|^-DENIED Redis is running',
    b'MemCache|MemCache|^ERROR\r\n',
    b'WebSocket|WebSocket|Server: WebSocket',
    b'SVN|SVN|^\( success \( 2 2 \( \) \( edit-pipeline svndiff1',
    b'Dubbo|Dubbo|^Unsupported command',
    b'HTTP|Elasticsearch|cluster_name.*elasticsearch',
    b'RabbitMQ|RabbitMQ|^AMQP\x00\x00\t\x01',
    b'Pyspider|Pyspider|HTTP.*Dashboard - pyspider',
    b'HTTPS|HTTPS|Instead use the HTTPS scheme to access',
    b'HTTPS|HTTPS|HTTP request was sent to HTTPS',
    b'HTTPS|HTTPS|HTTP request to an HTTPS server',
    b'HTTPS|HTTPS|Location: https',
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
        '888': '宝塔',
        '993': 'IMAPS',
        '1080': 'Proxy',
        '1099': 'JavaRMI',
        '1352': 'Lotus',
        '1433': 'MSSQL',
        '1521': 'Oracle',
        '1723': 'PPTP',
        '2082': 'CPanel',
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
        '10050': 'Zabbix',
        '8291': 'RouterOS',
        '9200': 'Elasticsearch',
        '11211': 'Memcached',
        '27017': 'MongoDB',
        '50070': 'Hadoop'
    }

    for k, v in SERVER.items():
        if k == port:
            return v
    return 'Unknown'


PORTS = [
    21, 22, 23, 25, 26, 34, 37, 42, 43, 45, 47, 49, 53, 56, 67, 69, 70, 76, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 91, 95, 99, 100, 106, 110, 111, 115, 119, 123, 129, 135, 136, 137, 139, 143, 146, 161, 163, 175, 179, 181,
    195, 199, 209, 211, 222, 233, 234, 258, 259, 264, 280, 301, 306, 311, 340, 344, 345, 363, 366, 369, 370, 389, 425,
    427, 434, 435, 443, 444, 445, 456, 458, 464, 465, 481, 487, 488, 497, 500, 502, 503, 512, 513, 514, 515, 520, 523,
    524, 530, 541, 548, 554, 555, 563, 567, 587, 593, 600, 623, 625, 626, 631, 635, 636, 646, 648, 656, 660, 666, 678,
    683, 687, 691, 700, 705, 708, 711, 714, 720, 722, 726, 749, 751, 765, 771, 777, 780, 783, 787, 789, 800, 801, 808,
    843, 873, 880, 888, 889, 890, 892, 894, 898, 901, 902, 910, 981, 985, 987, 990, 992, 993, 994, 995, 996, 999, 1000,
    1001, 1002, 1003, 1007, 1010, 1011, 1021, 1023, 1024, 1025, 1026, 1050, 1068, 1080, 1087, 1088, 1089, 1090, 1095,
    1099, 1102, 1111, 1112, 1114, 1117, 1119, 1126, 1141, 1145, 1154, 1169, 1177, 1183, 1192, 1200, 1201, 1213, 1234,
    1236, 1238, 1243, 1244, 1259, 1277, 1287, 1296, 1311, 1314, 1322, 1325, 1328, 1334, 1352, 1386, 1400, 1415, 1417,
    1433, 1434, 1443, 1455, 1461, 1471, 1494, 1500, 1503, 1510, 1512, 1515, 1516, 1521, 1524, 1533, 1551, 1556, 1580,
    1583, 1594, 1599, 1600, 1604, 1617, 1641, 1658, 1666, 1700, 1717, 1718, 1723, 1741, 1755, 1761, 1777, 1801, 1805,
    1812, 1819, 1873, 1875, 1883, 1900, 1911, 1914, 1920, 1935, 1947, 1962, 1974, 1984, 1991, 2000, 2001, 2002, 2003,
    2004, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2030, 2038, 2046, 2049, 2065, 2067,
    2068, 2081, 2082, 2083, 2086, 2087, 2096, 2103, 2111, 2119, 2121, 2122, 2123, 2126, 2135, 2144, 2152, 2170, 2179,
    2181, 2196, 2200, 2222, 2223, 2251, 2260, 2288, 2301, 2323, 2324, 2332, 2333, 2345, 2366, 2375, 2376, 2379, 2381,
    2399, 2401, 2404, 2425, 2433, 2455, 2480, 2483, 2484, 2492, 2500, 2522, 2525, 2526, 2546, 2557, 2601, 2604, 2627,
    2628, 2638, 2710, 2725, 2728, 2800, 2809, 2811, 2829, 2869, 2873, 2875, 2920, 2930, 2998, 3000, 3001, 3002, 3003,
    3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3127, 3128, 3129, 3130, 3132, 3168, 3211, 3221, 3233, 3260, 3269,
    3283, 3299, 3305, 3306, 3307, 3309, 3310, 3311, 3312, 3320, 3323, 3324, 3333, 3334, 3346, 3351, 3367, 3380, 3386,
    3388, 3389, 3391, 3396, 3404, 3435, 3456, 3460, 3476, 3478, 3493, 3517, 3527, 3536, 3537, 3541, 3542, 3543, 3546,
    3551, 3560, 3567, 3580, 3637, 3659, 3661, 3689, 3690, 3702, 3703, 3737, 3738, 3749, 3766, 3780, 3784, 3789, 3790,
    3794, 3806, 3809, 3814, 3839, 3851, 3869, 3871, 3873, 3878, 3880, 3889, 3899, 3905, 3914, 3918, 3920, 3940, 3945,
    3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4005, 4006, 4010, 4011, 4018, 4022, 4040, 4041, 4045, 4063, 4064,
    4070, 4096, 4100, 4111, 4129, 4142, 4200, 4224, 4242, 4243, 4279, 4321, 4343, 4344, 4369, 4396, 4399, 4400, 4440,
    4443, 4444, 4445, 4449, 4500, 4546, 4550, 4567, 4647, 4662, 4664, 4730, 4748, 4782, 4786, 4800, 4840, 4848, 4849,
    4873, 4880, 4899, 4911, 4949, 4950, 4998, 5000, 5001, 5002, 5003, 5006, 5007, 5008, 5009, 5030, 5033, 5051, 5054,
    5060, 5070, 5080, 5087, 5094, 5100, 5101, 5102, 5120, 5152, 5190, 5200, 5214, 5222, 5253, 5269, 5280, 5298, 5353,
    5354, 5357, 5405, 5414, 5431, 5432, 5433, 5440, 5455, 5500, 5510, 5544, 5550, 5554, 5555, 5556, 5560, 5566, 5577,
    5601, 5631, 5632, 5633, 5657, 5666, 5672, 5678, 5683, 5718, 5730, 5758, 5800, 5801, 5815, 5822, 5825, 5850, 5858,
    5859, 5862, 5873, 5877, 5900, 5901, 5915, 5922, 5925, 5938, 5950, 5952, 5960, 5984, 5985, 5986, 5999, 6000, 6001,
    6002, 6003, 6009, 6014, 6025, 6042, 6059, 6060, 6061, 6080, 6082, 6106, 6112, 6123, 6129, 6156, 6162, 6263, 6346,
    6364, 6379, 6389, 6390, 6465, 6489, 6502, 6510, 6543, 6547, 6566, 6580, 6588, 6646, 6661, 6664, 6666, 6667, 6680,
    6686, 6689, 6692, 6699, 6768, 6776, 6779, 6788, 6789, 6792, 6811, 6839, 6869, 6881, 6901, 6969, 6970, 6987, 7000,
    7001, 7002, 7003, 7004, 7005, 7006, 7007, 7009, 7010, 7019, 7025, 7047, 7070, 7071, 7080, 7090, 7100, 7103, 7106,
    7172, 7180, 7216, 7218, 7272, 7273, 7277, 7306, 7307, 7374, 7402, 7435, 7443, 7474, 7475, 7496, 7512, 7547, 7548,
    7549, 7576, 7625, 7627, 7657, 7670, 7676, 7677, 7741, 7777, 7778, 7779, 7780, 7800, 7809, 7879, 7890, 7903, 7905,
    7911, 7980, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8011, 8013, 8015, 8019, 8021, 8022,
    8023, 8028, 8030, 8031, 8042, 8045, 8050, 8060, 8069, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8106, 8111, 8112, 8123, 8126, 8139, 8140, 8161,
    8180, 8181, 8182, 8191, 8192, 8200, 8205, 8212, 8222, 8254, 8283, 8291, 8300, 8307, 8323, 8333, 8334, 8341, 8383,
    8384, 8390, 8399, 8400, 8402, 8423, 8433, 8443, 8485, 8499, 8500, 8554, 8586, 8600, 8611, 8649, 8651, 8652, 8654,
    8687, 8688, 8701, 8769, 8788, 8800, 8834, 8843, 8848, 8873, 8878, 8879, 8880, 8881, 8882, 8883, 8884, 8885, 8888,
    8889, 8890, 8891, 8892, 8899, 8912, 8913, 8914, 8964, 8980, 8983, 8990, 8994, 8998, 8999, 9000, 9001, 9002, 9003,
    9004, 9009, 9010, 9014, 9040, 9042, 9043, 9044, 9045, 9046, 9047, 9050, 9051, 9060, 9061, 9062, 9063, 9064, 9065,
    9071, 9080, 9081, 9090, 9091, 9092, 9093, 9097, 9100, 9110, 9151, 9160, 9166, 9180, 9191, 9192, 9200, 9207, 9220,
    9290, 9293, 9300, 9306, 9352, 9353, 9394, 9415, 9418, 9443, 9485, 9495, 9500, 9527, 9528, 9535, 9575, 9595, 9596,
    9600, 9618, 9666, 9697, 9700, 9701, 9780, 9789, 9797, 9798, 9833, 9866, 9869, 9876, 9898, 9899, 9900, 9901, 9903,
    9917, 9929, 9943, 9944, 9968, 9981, 9990, 9991, 9992, 9993, 9994, 9995, 9996, 9997, 9998, 9999, 10000, 10001, 10003,
    10004, 10009, 10010, 10012, 10023, 10050, 10051, 10080, 10082, 10086, 10101, 10180, 10202, 10215, 10240, 10243,
    10303, 10404, 10505, 10554, 10566, 10606, 10621, 10626, 10689, 10707, 10778, 10808, 11000, 11001, 11010, 11111,
    11211, 11212, 11300, 11313, 11371, 11380, 11381, 11414, 11433, 11451, 11515, 11521, 11616, 11717, 11818, 11967,
    12000, 12020, 12081, 12121, 12123, 12124, 12133, 12174, 12180, 12222, 12265, 12306, 12311, 12323, 12345, 12420,
    12424, 12525, 12580, 12626, 12727, 12828, 12888, 13000, 13030, 13080, 13131, 13180, 13189, 13223, 13232, 13280,
    13290, 13306, 13333, 13382, 13384, 13385, 13386, 13387, 13389, 13399, 13434, 13456, 13535, 13579, 13580, 13590,
    13599, 13636, 13680, 13722, 13737, 13782, 13783, 13838, 13880, 14000, 14003, 14040, 14141, 14147, 14238, 14242,
    14343, 14444, 14514, 14545, 14646, 14747, 14848, 14899, 15000, 15050, 15151, 15252, 15353, 15432, 15454, 15555,
    15656, 15660, 15742, 15757, 15858, 15900, 16000, 16010, 16012, 16016, 16018, 16060, 16080, 16113, 16161, 16262,
    16363, 16379, 16384, 16464, 16565, 16666, 16767, 16868, 16992, 16993, 17000, 17001, 17027, 17070, 17171, 17272,
    17373, 17474, 17575, 17676, 17777, 17778, 17877, 17878, 17988, 18000, 18040, 18080, 18081, 18090, 18100, 18101,
    18180, 18181, 18245, 18282, 18383, 18484, 18505, 18585, 18686, 18787, 18888, 18889, 18988, 19000, 19002, 19003,
    19101, 19128, 19130, 19134, 19136, 19200, 19283, 19315, 19350, 19703, 19780, 19801, 19842, 19891, 20000, 20005,
    20027, 20029, 20031, 20080, 20101, 20193, 20202, 20303, 20404, 20505, 20547, 20606, 20707, 20808, 20828, 21000,
    21005, 21008, 21010, 21011, 21025, 21100, 21111, 21207, 21212, 21313, 21379, 21381, 21414, 21433, 21515, 21521,
    21546, 21571, 21616, 21717, 21818, 22000, 22012, 22020, 22022, 22121, 22222, 22323, 22345, 22424, 22525, 22626,
    22727, 22828, 22939, 22986, 23000, 23023, 23030, 23131, 23232, 23306, 23307, 23333, 23389, 23424, 23434, 23502,
    23535, 23636, 23737, 23838, 24000, 24022, 24040, 24141, 24212, 24242, 24343, 24444, 24545, 24646, 24747, 24800,
    24848, 24899, 25000, 25050, 25105, 25151, 25252, 25353, 25432, 25454, 25555, 25565, 25656, 25757, 25858, 25900,
    26000, 26060, 26161, 26214, 26262, 26363, 26379, 26464, 26565, 26666, 26767, 26868, 27000, 27015, 27016, 27017,
    27018, 27019, 27070, 27171, 27272, 27373, 27374, 27474, 27545, 27575, 27650, 27676, 27715, 27777, 27878, 28000,
    28015, 28017, 28080, 28088, 28181, 28201, 28282, 28383, 28484, 28561, 28585, 28686, 28787, 28888, 29000, 29090,
    29200, 29988, 30000, 30001, 30100, 30101, 30202, 30303, 30404, 30505, 30606, 30707, 30718, 30808, 30951, 31000,
    31010, 31025, 31038, 31111, 31212, 31313, 31337, 31414, 31433, 31515, 31521, 31616, 31717, 31818, 32000, 32020,
    32121, 32222, 32323, 32400, 32424, 32525, 32626, 32727, 32764, 32768, 32769, 32770, 32771, 32772, 32773, 32828,
    33000, 33030, 33131, 33232, 33306, 33333, 33354, 33389, 33434, 33535, 33600, 33636, 33737, 33838, 33890, 33899,
    34000, 34040, 34141, 34242, 34343, 34444, 34545, 34646, 34747, 34848, 34899, 35000, 35050, 35151, 35246, 35252,
    35353, 35432, 35454, 35500, 35555, 35656, 35757, 35858, 35900, 36000, 36060, 36161, 36257, 36262, 36363, 36379,
    36464, 36565, 36666, 36695, 36767, 36868, 37000, 37070, 37171, 37272, 37373, 37474, 37575, 37676, 37777, 37878,
    38000, 38080, 38089, 38181, 38190, 38282, 38292, 38383, 38484, 38585, 38686, 38787, 38888, 39000, 39200, 39322,
    39999, 40000, 40001, 40011, 40049, 40101, 40193, 40202, 40303, 40404, 40505, 40606, 40650, 40707, 40710, 40808,
    40911, 41000, 41010, 41111, 41212, 41313, 41414, 41433, 41511, 41515, 41521, 41616, 41706, 41717, 41818, 42000,
    42020, 42121, 42178, 42222, 42323, 42424, 42510, 42525, 42626, 42727, 42828, 43000, 43030, 43131, 43232, 43306,
    43333, 43382, 43389, 43434, 43535, 43636, 43737, 43838, 43847, 44000, 44040, 44141, 44176, 44242, 44343, 44444,
    44501, 44545, 44646, 44747, 44818, 44848, 44899, 45000, 45050, 45100, 45151, 45252, 45353, 45432, 45443, 45454,
    45555, 45656, 45678, 45757, 45858, 45900, 46000, 46060, 46161, 46262, 46336, 46363, 46379, 46464, 46565, 46666,
    46767, 46868, 47000, 47001, 47070, 47171, 47272, 47373, 47474, 47575, 47676, 47777, 47808, 47878, 48000, 48080,
    48181, 48282, 48383, 48484, 48585, 48686, 48787, 48888, 48899, 49000, 49152, 49153, 49154, 49155, 49156, 49163,
    49165, 49167, 49200, 49400, 49430, 50000, 50006, 50010, 50011, 50015, 50030, 50050, 50060, 50070, 50100, 50101,
    50202, 50300, 50303, 50389, 50404, 50500, 50505, 50606, 50636, 50707, 50800, 50808, 51000, 51010, 51103, 51106,
    51111, 51148, 51212, 51313, 51414, 51433, 51493, 51515, 51521, 51616, 51717, 51818, 51980, 52000, 52020, 52121,
    52222, 52272, 52323, 52424, 52516, 52525, 52626, 52673, 52727, 52822, 52828, 52848, 52869, 53000, 53030, 53131,
    53232, 53306, 53333, 53389, 53413, 53434, 53535, 53636, 53737, 53838, 54000, 54040, 54045, 54138, 54141, 54242,
    54291, 54328, 54343, 54444, 54545, 54646, 54747, 54848, 54899, 55000, 55050, 55151, 55252, 55353, 55432, 55443,
    55454, 55553, 55554, 55555, 55600, 55656, 55757, 55858, 55900, 56000, 56060, 56161, 56262, 56363, 56379, 56464,
    56565, 56666, 56767, 56868, 57000, 57070, 57171, 57272, 57294, 57373, 57474, 57575, 57676, 57777, 57797, 57878,
    58000, 58001, 58002, 58080, 58181, 58282, 58383, 58484, 58585, 58686, 58787, 58888, 59000, 59200, 60000, 60001,
    60020, 60101, 60202, 60303, 60404, 60443, 60505, 60606, 60707, 60808, 60893, 61000, 61010, 61111, 61212, 61313,
    61414, 61515, 61532, 61616, 61717, 61818, 61900, 62000, 62020, 62078, 62121, 62222, 62323, 62333, 62424, 62525,
    62626, 62727, 62828, 63000, 63030, 63131, 63232, 63331, 63333, 63434, 63535, 63636, 63737, 63821, 63838, 64040,
    64141, 64242, 64343, 64444, 64545, 64623, 64646, 64680, 64738, 64747, 64848, 65000, 65024, 65050, 65129, 65151,
    65252, 65353, 65389, 65454
]

# 添加端口段
PORTS.extend([i for i in range(80, 90)])
PORTS.extend([i for i in range(800, 900)])
PORTS.extend([i for i in range(8000, 9000)])
PORTS.extend([i for i in range(10000, 11000)])
PORTS = list(set(PORTS))

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
            # 这里是统计总共开放端口，有些服务器一扫描就全端口开放当大于某个端口数量时则不记录
            if len(self.port) < 30:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((ip, int(port)))
                # 建立3次握手成功
                if result == 0:
                    try:
                        for i in PROBE:
                            sock.sendall(i.encode())
                            response = sock.recv(256)
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
    # ScanPort('127.0.0.1', 'result').pool()
    print(len(PORTS))
    end_time = time.time()
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
