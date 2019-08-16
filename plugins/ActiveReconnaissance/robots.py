# coding=utf-8
import re
import logging
from lib.Requests import Requests


def robots(url):
    result = ''
    try:
        req = Requests()
        r = req.get(url + '/robots.txt')
        if r.status_code == 200 and '<html' not in r.text:
            result = re.findall(r"/[\w\?\.=/]+/?", r.text)
        if result:
            return list(set(result))
    except (UnboundLocalError, AttributeError):
        pass
    except Exception as e:
        logging.exception(e)
