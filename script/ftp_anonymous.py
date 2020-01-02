#!/usr/bin/python
import ftplib

from lib.verify import verify

vuln = ['FTP', '21']


def check(url, ip, ports, apps):
    if verify(vuln, ports, apps):
        try:
            ftp = ftplib.FTP(ip)
            ftp.login('anonymous', 'anonymous')
            return 'FTP anonymous Login'
        except Exception as e:
            pass
