# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import geoip2.database
import sys
from lib.bcolors import bcolors


def geoip(ipaddr):
    # 获取IP地理位置
    geoip2.database
    reader = geoip2.database.Reader('data/GeoLite2-City.mmdb')
    try:
        response = reader.city(ipaddr)
        country = response.country.names["zh-CN"]
        site = response.subdivisions.most_specific.names.get("zh-CN")
        if not site:
            site = ''
        city = response.city.names.get("zh-CN")
        if not city:
            city = ''
        address = '{} {} {}'.format(country, site, city)
    except Exception as e:
        address = 'None'
    sys.stdout.write(bcolors.RED + "GeoIP：\n" + bcolors.ENDC)
    sys.stdout.write(bcolors.OKGREEN + '[+] Address: {}\n'.format(address) + bcolors.ENDC)
    sys.stdout.write(bcolors.OKGREEN + '[+] Ipaddr: {}\n'.format(ipaddr) + bcolors.ENDC)
    return address
