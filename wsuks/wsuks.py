#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import traceback
from wsuks.helpers.logger import initLogger
from wsuks.helpers.argparser import initParser, printBanner
from wsuks.helpers.sysvolparser import SysvolParser


class Wsuks:
    def __init__(self):
        self.logger = logging.getLogger()

    def run(self):
        self.logger.info('This is an info message')
        self.logger.debug('This is a debug message')
        self.logger.warning('This is a warning message')
        self.logger.error('This is an error message')


def main():
    printBanner()
    args = initParser()
    initLogger(debug=args.debug)
    logger = logging.getLogger()
    logger.info(args)

    # Get the WSUS server IP and Port from the sysvol share
    sysvolparser = SysvolParser()
    smbConnection = sysvolparser.getSMBConnection(args, args.domain, args.username, args.password, args.target_ip, args.lmhash, args.nthash)
    wsusIp, wsusPort = sysvolparser.findWsusServer(smbConnection)
    sysvolparser.close(smbConnection)

    # Start Arp Spoofing


    wsuks = Wsuks()
    wsuks.run()


if __name__ == '__main__':
    main()
