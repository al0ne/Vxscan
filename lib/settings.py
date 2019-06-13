import time

# 全局超时时间
TIMEOUT = 5
# 要排除的状态吗
BLOCK_CODE = [
    301, 403, 308, 404, 405, 406, 408, 411, 417, 429, 493, 502, 503, 504, 999
]
# 设置扫描线程
THREADS = 100
# 要排除的 内容类型
BLOCK_CONTYPE = [
    'image/jpeg', 'image/gif', 'image/png', 'application/javascript',
    'application/x-javascript', 'text/css', 'application/x-shockwave-flash',
    'text/javascript', 'image/x-icon'
]

# 是否跳过目录扫描
SKIP = True

# 无效的404页面
# page404 = [
#     'page404"', "404.png", "找不到页面", "Not Found", "访问的页面不存在",
#     '<html><head><script type="text/javascript">',
#     '\\xe9\\xa1\\xb5\\xe9\\x9d\\xa2\\xe4\\xb8\\x8d\\xe5\\xad\\x98\\xe5\\x9c\\xa8',
#     "page does't exist"
# ]

# 保存的文件名
html_name = time.strftime("%Y%m%d%H%M%S", time.localtime())

# shodan
shodan_api = ''

# VT接口
virustotal_api = 'xxxxxxxxxxxxxxxxxxxxxxxxxx'

COOKIE = {'Cookie': 'Vxscan 1.0'}

PASS = ['123456789', 'password', 'passwd', 'a123456', '123456', 'a123456789', '1234567890', 'qq123456', 'abc123456',
        '123456a',
        '123456789a', '147258369', 'zxcvbnm', 'admin', '987654321', '12345678910', 'abc123', 'qq123456789',
        '123456789.', 'root', '666666', '88888888',
        '7708801314520', '5201314520', 'q123456', '123456abc', '1233211234567', '123123123', '123456.',
        '0123456789', 'asd123456', 'aa123456', '135792468', 'q123456789', 'abcd123456', '12345678900',
        'zxcvbnm123', 'w123456', 'abc123456789', '111111',
        'qwertyuiop', '1314520520', '1234567891', 'qwe123456', 'asd123', '000000', '1472583690', '1357924680',
        '789456123', '123456789abc', 'z123456', '1234567899', 'aaa123456', 'abcd1234', 'www123456', '123456789q',
        '123abc', 'qwe123', 'w123456789', '7894561230', '123456qq', 'zxc123456', '123456789qq', '1111111111',
        '111111111', '12344321', 'qazwsxedc', 'qwerty', '123456..', 'zxc123', 'asdfghjkl',
        '0000000000', '1234554321', '123456q', '123456aa', '9876543210', '110120119', 'qaz123456', 'qq5201314',
        '123698745', '5201314', '000000000', 'as123456', '123123', '5841314520', 'z123456789',
        'a123123', 'caonima', 'a5201314', 'wang123456', 'abcd123', '123456789..', '123456asd',
        'aa123456789', '741852963', 'a12345678', 'qaz123', 'tomcat', 'jboss', 'weblogic', '1qaz2wsx']
