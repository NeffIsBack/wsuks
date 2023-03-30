#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import sys


class WsuksFormatter(logging.Formatter):
    '''
    Prefixing logged messages through the custom attribute 'bullet'.
    '''

    def __init__(self):
        logging.Formatter.__init__(self, '%(bullet)s %(message)s', None)

    def format(self, record):
        if record.levelno == logging.INFO:
            record.bullet = '[*]'
        elif record.levelno == logging.DEBUG:
            record.bullet = '[+]'
        elif record.levelno == logging.WARNING:
            record.bullet = '[!]'
        else:
            record.bullet = '[-]'

        return logging.Formatter.format(self, record)


class WsuksFormatterTimeStamp(WsuksFormatter):
    '''
    Prefixing logged messages through the custom attribute 'bullet'.
    '''

    def __init__(self):
        logging.Formatter.__init__(self, '[%(asctime)-15s] %(bullet)s %(message)s', None)

    def formatTime(self, record):
        return WsuksFormatter.formatTime(self, record, datefmt="%Y-%m-%d %H:%M:%S")


def initLogger(ts=False, debug=False):
    handler = logging.StreamHandler(sys.stdout)
    if ts:
        handler.setFormatter(WsuksFormatterTimeStamp())
    else:
        handler.setFormatter(WsuksFormatter())
    logging.getLogger().addHandler(handler)
    
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
