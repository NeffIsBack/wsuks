#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import traceback
from impacket.smbconnection import SMBConnection

class SysvolParser():
    def __init__(self):
        self.logger = logging.getLogger()
        self.smbClient = None
        self.share = "SYSVOL"
        self.WsusIp = None
        self.WsusPort = None # Should be 8530
    
    def getSMBConnection(self, args, domain, username, password, address, lmhash, nthash):
        """
        Create a SMB connection to the target
        """
        # SMB Login would be ready for kerberos or NTLM Hashes Authentication if it is needed
        try:
            self.smbClient = SMBConnection(address, args.target_ip, sess_port=int(args.port))

            if args.k is True:
                self.smbClient.kerberosLogin(username, password, domain, lmhash, nthash, args.aesKey, args.dc_ip)
            else:
                self.smbClient.login(username, password, domain, lmhash, nthash)
            if self.smbClient.isGuestSession() > 0:
                self.logger.debug("GUEST Session Granted")
            else:
                self.logger.debug("USER Session Granted")
        except Exception as e:
            self.logger.error("Error: {}".format(e))
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()

        return self.smbClient

    def close(smbClient: SMBConnection):
        """
        Close the SMB connection
        """
        smbClient.close()

    def findWsusServer(self, smbClient: SMBConnection):
        """
        Get the WSUS server from the sysvol share
        
        :param smbClient: SMB connection to Domain Controller
        :return: WSUS server IP and Port
        """
        return self.WsusIp, self.WsusPort