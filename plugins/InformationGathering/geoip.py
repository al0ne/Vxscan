# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import logging

import geoip2.database
import geoip2.errors

from lib.cli_output import console


def geoip(ipaddr):
    # 获取IP地理位置
    try:
        reader = geoip2.database.Reader('data/GeoLite2-City.mmdb')
        response = reader.city(ipaddr)
        country = response.country.names["zh-CN"]
        site = response.subdivisions.most_specific.names.get("zh-CN")
        if not site:
            site = ''
        city = response.city.names.get("zh-CN")
        if not city:
            city = ''
        address = '{} {} {}'.format(country, site, city)
    except FileNotFoundError:
        address = 'Geoip File Not Found'
    except (KeyError, geoip2.errors.AddressNotFoundError):
        address = 'Address Not In Databases'
    except Exception as e:
        logging.exception(e)
        address = 'None'
    console('GeoIP', ipaddr, 'Address: {}\n'.format(address))
    console('GeoIP', ipaddr, 'Ipaddr: {}\n'.format(ipaddr))
    return address


if __name__ == "__main__":
    geoip('1.1.1.1')
