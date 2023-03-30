#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from wsuks.helpers.logger import initLogger
from wsuks.helpers.argparser import initParser, printBanner


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

    wsuks = Wsuks()
    wsuks.run()


if __name__ == '__main__':
    main()
