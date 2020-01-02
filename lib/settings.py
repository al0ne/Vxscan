# coding=utf-8

# True 调用asyncio+aiohttp+uvloop 异步扫描
# False 调用传统多线程扫描
METHOD = True

# 全局超时时间
TIMEOUT = 5

# 国家验证
VERIFY_COUNTRY = False

# 要排除的状态吗
BLOCK_CODE = [
    0, 308, 400, 401, 403, 404, 405, 406, 408, 410, 411, 414, 417, 418, 419, 429, 461, 493, 500, 502, 503, 504, 999
]
# 设置扫描线程
THREADS = 100
# 要排除的 内容类型
BLOCK_CONTYPE = [
    'image/jpeg', 'image/gif', 'image/png', 'text/css', 'application/x-shockwave-flash', 'image/x-icon', 'x-icon'
]

# 是否启动目录扫描
SCANDIR = True

# 是否启动POC插件
POC = True

# 是否开启抓取插件
CRAWL = False

# 如果存在于结果db中就跳过
CHECK_DB = False

# 无效的404页面
PAGE_404 = [
    'page_404"', "404.png", '找不到页面', '页面找不到', "访问的页面不存在", "page does't exist", 'notice_404', '404 not found',
    '<title>错误</title>', '内容正在加载', '提示：发生错误', '无法加载控制器', '无法加载模块:', '当前页面不存在或已删除', '>错误：操作无法执行', '您访问的网站出错了',
    'URL不符合规定', '没有找到站点', '您所访问的页面不存在', 'File not found', 'Page not found', 'Error code: 404', '>您所提交的请求含有不合法的参数',
    '>404 Error', 'Web server is returning an unknown error', 'website not found', '"page404"', '<p>页面找不到了',
    '抱歉，找不到此页面', 'page now can not be found', '您访问的资源不存在', 'error404 ', '/404.jpg', '您打开的页面未能找到', '"statusCode":404',
    '你访问的页面不存在', '您访问的页面不存在或者已经删除', '你想查看的页面已被转移或删除了', '404 - 页面没找到', '404</h1>', '指定的主题不存在或已被删除或正在被审核',
    '404 Not Found', '抱歉，此页面不存在', '抱歉，此頁面不存在', '"404page"', '>404 PAGE', '"search-404"', 'that page doesn’t exist!',
    '"error.404.header"', '"error.404.link"', 'error_pages', '?ref=404"', '>未找到页面<', '您的请求在Web服务器中没有找到对应的站点',
    'You need to enable JavaScript to run this app', '<title>404 - 页面不存在'
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
COOKIE = 'random'
# COOKIE = {'Cookie': 'SRCtest'}
