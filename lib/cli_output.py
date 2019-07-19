import sys
import pyfiglet
from lib.settings import POC, THREADS, SCANDIR, PING
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
    sys.stdout.write(bcolors.OKBLUE + str(PING) + "\n\n" + bcolors.ENDC)