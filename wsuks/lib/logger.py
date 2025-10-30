
import logging
import sys
from termcolor import colored


class WsuksFormatter(logging.Formatter):
    """Prefixing logged messages through the custom attribute 'bullet'."""

    def __init__(self):
        logging.Formatter.__init__(self, "%(bullet)s %(message)s", None)

    def format(self, record):
        if record.levelno == logging.DEBUG:
            record.bullet = colored("DEBUG", "magenta", attrs=["bold"])
        elif record.levelno == logging.INFO:
            record.bullet = colored("[*]", "blue", attrs=["bold"])
        elif record.levelno == logging.SUCCESS:
            record.bullet = colored("[+]", "green", attrs=["bold"])
        elif record.levelno == logging.WARNING:
            record.bullet = colored("[!]", "yellow", attrs=["bold"])
        elif record.levelno == logging.ERROR:
            record.bullet = colored("[-]", "red", attrs=["bold"])
        elif record.levelno == logging.CRITICAL:
            record.bullet = colored("[CRITICAL]", "red", attrs=["bold", "reverse"])
        elif record.levelno:
            record.bullet = "[ERROR]"

        return logging.Formatter.format(self, record)


class WsuksFormatterTimeStamp(WsuksFormatter):
    """Prefixing logged messages through the custom attribute 'bullet'."""

    def __init__(self):
        logging.Formatter.__init__(self, "[%(asctime)-15s] %(bullet)s %(message)s", None)

    def formatTime(self, record, datefmt=None):
        return WsuksFormatter.formatTime(self, record, datefmt="%Y-%m-%d %H:%M:%S")


def addSuccessLogLevel(logger):
    logging.SUCCESS = 25  # between WARNING and INFO
    logging.addLevelName(logging.SUCCESS, "SUCCESS")

    def success(self, msg, *args, **kwargs):
        logger._log(25, msg, args, **kwargs)
    logging.getLoggerClass().success = success


def initLogger(ts=False, debug=False):
    """
    Initialize wsuks logger with specified logging level, add formatter, handler and success log level

    :param ts: Add timestamp to log messages
    :param debug: Set logging level to DEBUG
    :return: logger
    """
    handler = logging.StreamHandler(sys.stdout)
    if ts:
        handler.setFormatter(WsuksFormatterTimeStamp())
    else:
        handler.setFormatter(WsuksFormatter())

    logger = logging.getLogger("wsuks")
    logger.propagate = False
    root_logger = logging.getLogger()

    logger.addHandler(handler)
    root_logger.addHandler(handler)

    if debug:
        logger.setLevel(logging.DEBUG)
        root_logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        root_logger.setLevel(logging.INFO)

    addSuccessLogLevel(logger)
    addSuccessLogLevel(root_logger)

    return logger
