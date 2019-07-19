# coding = utf-8

import sqlite3
import time
import hashlib
import sys
from lib.bcolors import bcolors
from lib.url import parse_host


class Sqldb():
    
    def __init__(self, dbname):
        self.name = dbname
        self.conn = sqlite3.connect(self.name + '.db', check_same_thread=False)
    
    def commit(self):
        self.conn.commit()
    
    def close(self):
        self.conn.close()
    
    def create_webinfo_db(self):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS webinfo (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time varchar(255),
                domain varchar(255),
                waf varchar(255) DEFAULT '',
                title varchar(255) DEFAULT '',
                apps varchar(255) DEFAULT '',
                server varchar(255) DEFAULT '',
                security varchar(255) DEFAULT '',
                address varchar(255) DEFAULT '',
                ipaddr varchar(255) DEFAULT '',
                os varchar(255) DEFAULT '',
                pdns varchar(255) DEFAULT '',
                reverseip varchar(255) DEFAULT '',
                md5 varchar(40) UNIQUE
                )
                """
            )
        except sqlite3.OperationalError as e:
            print(e)
    
    def create_ports(self):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time varchar(255),
                ipaddr varchar(255),
                service varchar(255) DEFAULT '',
                port varchar(255) DEFAULT '',
                md5 varchar(40) UNIQUE
                )
                """
            )
        except Exception as e:
            print(e)
    
    def create_urls(self):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS urls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time varchar(255),
                domain varchar(255) DEFAULT '',
                title varchar(255) DEFAULT '',
                url varchar(255) DEFAULT '',
                contype varchar(255) DEFAULT '',
                rsp_len varchar(255) DEFAULT '',
                rsp_code varchar(255) DEFAULT '',
                md5 varchar(40) UNIQUE
                )
                """
            )
        except Exception as e:
            print(e)
    
    def create_vuln(self):
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS vuln (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                time varchar(255),
                domain varchar(255),
                vuln varchar(255) DEFAULT '',
                md5 varchar(40) UNIQUE
                )
                """
            )
        except:
            pass
    
    def insert_webinfo(self, query, values):
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, values)
            self.commit()
        except Exception as e:
            print(e)
    
    def insert_ports(self, query, values):
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, values)
            self.commit()
        except Exception as e:
            print(e)
    
    def insert_urls(self, query, values):
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, values)
        except Exception as e:
            print(e)
    
    def insert_vuln(self, query, values):
        try:
            cursor = self.conn.cursor()
            cursor.execute(query, values)
        except:
            pass
    
    def get_urls(self, urls):
        self.create_urls()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        for url in urls:
            for k, v in url.items():
                md5sum = hashlib.md5()
                strings = str(k) + str(v.get('title')) + str(v.get('url'))
                md5sum.update(strings.encode('utf-8'))
                md5 = md5sum.hexdigest()
                values = (
                    timestamp,
                    k,
                    v.get('title'),
                    k + v.get('url'),
                    v.get('contype'),
                    v.get('rsp_len'),
                    v.get('rsp_code'),
                    md5
                )
                query = "INSERT OR IGNORE INTO urls (time, domain, title, url, contype, rsp_len,rsp_code,md5) VALUES (?,?,?,?,?,?,?,?)"
                self.insert_urls(query, values)
        self.commit()
        self.close()
    
    def get_ports(self, ipaddr, ports):
        self.create_ports()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        for i in ports:
            service, port = i.split(':')
            md5sum = hashlib.md5()
            strings = str(ipaddr) + str(service) + str(port)
            md5sum.update(strings.encode('utf-8'))
            md5 = md5sum.hexdigest()
            values = (
                timestamp,
                ipaddr,
                service,
                port,
                md5
            )
            query = "INSERT OR IGNORE INTO ports (time, ipaddr, service, port, md5) VALUES (?,?,?,?,?)"
            self.insert_ports(query, values)
    
    def get_vuln(self, domain, vuln):
        self.create_vuln()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        for i in vuln:
            md5sum = hashlib.md5()
            strings = str(domain) + str(i)
            md5sum.update(strings.encode('utf-8'))
            md5 = md5sum.hexdigest()
            values = (
                timestamp,
                domain,
                i,
                md5
            )
            query = "INSERT OR IGNORE INTO vuln (time, domain, vuln, md5) VALUES (?,?,?,?)"
            self.insert_vuln(query, values)
        self.commit()
        self.close()
    
    def get_webinfo(self, webinfo):
        self.create_webinfo_db()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        for k, v in webinfo.items():
            apps = v.get('Webinfo').get('apps')
            if apps:
                apps = ' , '.join(apps)
            else:
                apps = None
            security = v.get('Webinfo').get('security')
            if not security:
                security = None
            else:
                security = ' , '.join(security)
            reverse_ip = v.get('Webinfo').get('reverseip')
            if reverse_ip:
                reverse_ip = ' , '.join(reverse_ip)
            else:
                reverse_ip = None
            waf = v.get('WAF')
            if waf == 'None':
                waf = None
            title = v.get('Webinfo').get('title')
            if not title:
                title = None
            address = v.get('Address')
            if address == 'None' or not address:
                address = None
            server = v.get('Webinfo').get('server')
            if server == 'None' or not server:
                server = None
            pdns = v.get('Webinfo').get('pdns')
            if pdns:
                pdns = ' , '.join(pdns)
            else:
                pdns = None
            os = v.get('OS')
            if not os or os == 'None':
                os = None
            ipaddr = v.get('Ipaddr')
            if not ipaddr or ipaddr == 'None':
                ipaddr = None
            md5sum = hashlib.md5()
            strings = str(k) + str(title) + str(server)
            md5sum.update(strings.encode('utf-8'))
            md5 = md5sum.hexdigest()
            values = (
                timestamp,
                k,
                waf,
                title,
                apps,
                server,
                security,
                address,
                ipaddr,
                os,
                pdns,
                reverse_ip,
                md5
            )
            query = "INSERT OR IGNORE INTO webinfo (time, domain, waf, title, apps, server, security, address, ipaddr, os, pdns, reverseip,md5) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
            self.insert_webinfo(query, values)
        self.commit()
        self.close()
    
    def query_db(self, hosts):
        result = []
        error = False
        for i in hosts:
            try:
                domain = parse_host(i)
                cursor = self.conn.cursor()
                sql = "select 1 from webinfo where domain = '{}' limit 1".format(domain)
                cursor.execute(sql)
                values = cursor.fetchall()
                if not values:
                    result.append(i)
                else:
                    sys.stdout.write(bcolors.OKGREEN + "{} In the db file\n".format(i) + bcolors.ENDC)
            except sqlite3.OperationalError:
                return hosts
            except Exception as e:
                error = True
        self.commit()
        self.close()
        if error:
            return hosts
        else:
            return result
    
    def query(self, sql):
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql)
            values = cursor.fetchall()
            return values
        except:
            pass
        finally:
            self.commit()
            self.close()
