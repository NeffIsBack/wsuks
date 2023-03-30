#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
from argparse import RawTextHelpFormatter
import importlib.metadata

__version__ = importlib.metadata.version("wsuks")


def printBanner():
    print(f"""
    __          __ _____  _    _  _  __  _____ 
    \ \        / // ____|| |  | || |/ / / ____|
     \ \  /\  / /| (___  | |  | || ' / | (___  
      \ \/  \/ /  \___ \ | |  | ||  <   \___ \ 
       \  /\  /   ____) || |__| || . \  ____) |
        \/  \/   |_____/  \____/ |_|\_\|_____/ 
                                                                                        
     Pentesting Tool for the WSUS MITM Attack
               Made by NeffIsBack
                 Version: {__version__}
""")


def initParser():
    example_text = """Examples:
    wsuks -t 192.168.0.10 -u User -p Password123 -dc-ip 192.168.0.1
    wsuks -t 192.168.0.10 -u User -p Password123 -dc-ip 192.168.0.1 -c "dir"
    wsuks -t 192-168-0-10 --WSUS-Server 192.168.0.2 -c "dir"
    """
    parser = argparse.ArgumentParser(prog='wsuks', epilog=example_text, formatter_class=RawTextHelpFormatter)

    parser.add_argument('-v', '--version', action='version', version='Current Version: %(prog)s 2.0')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')

    parser.add_argument('-t', '--target-ip', action='store_true', help='IP Address of the victim Client. (REQUIRED)', required=True)
    parser.add_argument('-e', '--executable', action='store_true', help='The executable to returned to the victim. It has to be signed by Microsoft (DEFAULT: PsExec64.exe)')
    parser.add_argument('-c', '--command', action='store_true', help='The command to execute on the victim. (DEFAULT: %(default)s)', default='whoami')

    simple = parser.add_argument_group('AUTOMATIC MODE', 'Discover the WSUS Server automatically by searching for GPOs in SYSVOL. (Default)')
    simple.add_argument('-u', '--username', action='store_true', help='Username to authenticate with. (Required in automatic Mode)')
    simple.add_argument('-p', '--password', action='store_true', help='Password to authenticate with. (Required in automatic Mode)')
    simple.add_argument('-dc-ip', action='store_true', help='IP Address of the domain controller. (Required in automatic Mode)')

    advanced = parser.add_argument_group('MANUAL MODE', 'If you know the WSUS Server, you can use this mode to skip the automatic discovery.')
    advanced.add_argument('--WSUS-Server', action='store_true', help='IP Address of the WSUS Server.')
    advanced.add_argument('--WSUS-Port', metavar='', type=int, default=8530, help='Port of the WSUS Server. (DEFAULT: %(default)s)')

    return parser.parse_args()
