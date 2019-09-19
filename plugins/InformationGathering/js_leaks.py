# coding=utf-8
# author: al0ne
# https://github.com/al0ne

import re
import time
import logging
from lib.Requests import Requests
import concurrent.futures


class JsLeaks():
    def __init__(self):
        self.result = []
        self.req = Requests()

    def pool(self, urls):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                result = {executor.submit(self.get_js, i): i for i in urls}
                for future in concurrent.futures.as_completed(result, timeout=3):
                    future.result()
        except (EOFError, concurrent.futures._base.TimeoutError):
            pass
        except Exception as e:
            logging.exception(e)

        return self.result

    def verify(self, text):
        result = True
        for i in text:
            if not re.search(r'^0\d\.\d+\.\d+\.\d+|google|png$|gif$|jpg$|\b\d+\.\d+\.0\.0', i):
                result = False
                break
        return result

    def get_js(self, url):
        r = self.req.get(url)
        regex = (
            # 匹配url
            r'\b(?:http:|https:)(?:[\w/\.]+)?(?:[a-zA-Z0-9_\-\.]{1,})\.(?:php|asp|ashx|jspx|aspx|jsp|json|action|html|txt|xml|do|js)\b',
            r'([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^\"|\']{0,}|))',
            # 匹配邮箱
            r'[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)+',
            # 匹配token或者密码泄露
            # 例如token = xxxxxxxx, 或者"apikey" : "xssss"
            r'\b(?:secret|secret_key|token|secret_token|auth_token|access_token|username|password|aws_access_key_id|aws_secret_access_key|secretkey|authtoken|accesstoken|access-token|authkey|client_secret|bucket|extr|HEROKU_API_KEY|SF_USERNAME|PT_TOKEN|id_dsa|clientsecret|client-secret|encryption-key|pass|encryption_key|encryptionkey|secretkey|secret-key|bearer|JEKYLL_GITHUB_TOKEN|HOMEBREW_GITHUB_API_TOKEN|api_key|api_secret_key|api-key|private_key|client_key|client_id|sshkey|ssh_key|ssh-key|privatekey|DB_USERNAME|oauth_token|irc_pass|dbpasswd|xoxa-2|xoxrprivate-key|private_key|consumer_key|consumer_secret|access_token_secret|SLACK_BOT_TOKEN|slack_api_token|api_token|ConsumerKey|ConsumerSecret|SESSION_TOKEN|session_key|session_secret|slack_token|slack_secret_token|bot_access_token|passwd|api|eid|sid|qid|api_key|apikey|userid|user_id|user-id|uid|private|BDUSS|stoken|imei|imsi|nickname|appid|uname)["\s]*(?::|=|=:|=>)["\s]*[a-z0-9A-Z]{8,64}',
            # 匹配
            r'(?:[^a-fA-F\d]|\b)(?:[a-fA-F\d]{32})(?:[^a-fA-F\d]|\b)',
            # 匹配 "/task/router" 这种路径
            r'"(/\w{3,}/\w{3,})"',
            # 匹配IP地址
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            # 匹配云泄露
            r'[\w]+\.cloudfront\.net',
            r'[\w\-.]+\.appspot\.com',
            r'[\w\-.]*s3[\w\-.]*\.?amazonaws\.com\/?[\w\-.]*',
            r'([\w\-.]*\.?digitaloceanspaces\.com\/?[\w\-.]*)',
            r'(storage\.cloud\.google\.com\/[\w\-.]+)',
            r'([\w\-.]*\.?storage.googleapis.com\/?[\w\-.]*)',
            # 匹配手机号
            r'(?:139|138|137|136|135|134|147|150|151|152|157|158|159|178|182|183|184|187|188|198|130|131|132|155|156|166|185|186|145|175|176|133|153|177|173|180|181|189|199|170|171)[0-9]{8}'
            # 匹配域名
            r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:biz|cc|club|cn|com|co|edu|fun|group|info|ink|kim|link|live|ltd|mobi|net|online|org|pro|pub|red|ren|shop|site|store|tech|top|tv|vip|wang|wiki|work|xin|xyz|me))'
        )
        for _ in regex:
            text = re.findall(_, r.text[:100000], re.M | re.I)
            if text is not None and self.verify(text):
                text = list(map(lambda x: url + ' Leaks: ' + x, text))
                self.result.extend(text)


if __name__ == "__main__":
    start_time = time.time()
    urls = ['https://www.baidu.com']
    jsparse = JsLeaks().pool(urls)
    print(jsparse)
    end_time = time.time()
    print('\nrunning {0:.3f} seconds...'.format(end_time - start_time))
