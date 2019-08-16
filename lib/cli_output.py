import sys
import time
import pyfiglet
from lib.settings import POC, THREADS, SCANDIR, PING, SOCKS5, CHECK_DB
from lib.bcolors import bcolors


def banner():
    ascii_banner = pyfiglet.figlet_format("Vxscan")
    print(bcolors.RED + ascii_banner + bcolors.ENDC)


def start_out(hosts):
    sys.stdout.write(bcolors.OKBLUE + "[*] https://github.com/al0ne/Vxscan\n" + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + "[*] Scanning POC: " + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + str(POC) + "\n" + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + "[*] Threads: " + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + str(THREADS) + "\n" + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + "[*] Target quantity: " + bcolors.ENDC)
    if type(hosts) == list:
        sys.stdout.write(bcolors.OKBLUE + str(len(hosts)) + "\n" + bcolors.ENDC)
    else:
        sys.stdout.write(bcolors.OKBLUE + '1' + "\n" + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + "[*] Scanning Dir: " + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + str(not SCANDIR) + "\n" + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + "[*] Ping: " + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + str(PING) + "\n" + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + "[*] CHECK_DB: " + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + str(CHECK_DB) + "\n" + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + "[*] Socks5 Proxy: " + bcolors.ENDC)
    sys.stdout.write(bcolors.OKBLUE + str(SOCKS5) + "\n\n" + bcolors.ENDC)


def console(plugins, domain, text):
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    timestamp = bcolors.OKBLUE + '[' + timestamp + ']' + bcolors.ENDC
    plugins = bcolors.RED + plugins + bcolors.ENDC
    text = bcolors.OKGREEN + text + bcolors.ENDC
    sys.stdout.write(timestamp + ' - ' + plugins + ' - ' + domain + '    ' + text)