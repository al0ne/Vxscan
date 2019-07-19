# coding=utf-8

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
SCANDIR = True

# 是否启动POC插件
POC = True

# 如果存在于结果db中就跳过
CHECK_DB = False

# 无效的404页面
PAGE_404 = [
    'page_404"', "404.png", '找不到页面', '页面找不到', "Not Found", "访问的页面不存在",
    "page does't exist", 'notice_404', '404 not found', '<title>错误</title>', '内容正在加载', '提示：发生错误', '<title>网站防火墙',
    '无法加载控制器'
]

# ping探测
PING = True

# 设置代理
# SOCKS5 = ('127.0.0.1', 1080)
SOCKS5 = ()

# shodan
SHODAN_API = ''

# VT接口
VIRUSTOTAL_API = ''

# 设置cookie
COOKIE = {'Cookie': 'test'}
