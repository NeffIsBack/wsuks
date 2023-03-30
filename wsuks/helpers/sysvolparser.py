#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logger
from impacket.smbconnection import SMBConnection

class SysvolParser():
    def __init__(self):
        self.logger = logger.getLogger()
    
    def _getSMBConnection(self, args, domain, username, password, address, lmhash, nthash):
        """
        Create a SMB connection to the target
        """

        smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))

        if args.k is True:
            smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
        else:
            smbClient.login(username, password, domain, lmhash, nthash)
        if smbClient.isGuestSession() > 0:
            self.logger.debug("GUEST Session Granted")
        else:
            self.logger.debug("USER Session Granted")
        return smbClient
