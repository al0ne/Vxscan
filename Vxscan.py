# coding:utf-8

# author: al0ne
# https://github.com/al0ne

import sys
import logging
import os
from lib.cli_output import banner
from lib.options import options

if os.path.exists('error.log'):
    os.remove('error.log')

if sys.version_info.major < 3:
    sys.stdout.write("Sorry, Vxscan requires Python 3\n")
    sys.exit(1)

if sys.version_info.minor < 6:
    sys.stdout.write("Sorry, Vxscan requires Python >= 3.6\n")
    sys.exit(1)

if __name__ == "__main__":
    
    logging.basicConfig(filename='error.log', level=logging.ERROR)
    logging.getLogger()
    
    try:
        banner()
        options()
    except KeyboardInterrupt:
        print('\nCtrl+C Stop running\n')
        sys.exit(0)
    except Exception as e:
        logging.exception(e)
