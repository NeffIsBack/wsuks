#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import sys
import traceback
from impacket.smbconnection import SMBConnection


class SysvolParser():
    def __init__(self):
        self.logger = logging.getLogger()
        self.smbClient = None
        self.share = "SYSVOL"
        self.wsusIp = None
        self.wsusPort = None  # Default 8530

    def _createSMBConnection(self, domain, username, password, dcIp, kerberos=False, lmhash='', nthash='', aesKey=''):
        """
        Create a SMB connection to the target
        """
        # SMB Login would be ready for kerberos or NTLM Hashes Authentication if it is needed
        #TODO: Fix remoteName in SMBConnection
        #TODO: Add Kerberos Authentication
        try:
            self.smbClient = SMBConnection(remoteName=dcIp, remoteHost=dcIp, sess_port=int(445))

            if kerberos is True:
                self.smbClient.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, dcIp)
            else:
                self.smbClient.login(username, password, domain, lmhash, nthash)
            self.logger.debug("SMB Connection Established")
            if self.smbClient.isGuestSession() > 0:
                self.logger.debug("GUEST Session Granted")
            else:
                self.logger.debug("USER Session Granted")
        except Exception as e:
            self.logger.error("Error: {}".format(e))
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()

        return self.smbClient

    def _extractWsusServerSYSVOL(self):
        return self.wsusIp, self.wsusPort

    def _closeConnection(self):
        """
        Close the SMB connection
        """
        self.smbClient.close()
        self.logger.debug("SMB Connection Closed")

    def findWsusServer(self, domain, username, password, dcIp):
        """
        Get the WSUS server from the sysvol share

        :param smbClient: SMB connection to Domain Controller
        :return: WSUS server IP and Port
        """
        try:
            self._createSMBConnection(domain, username, password, dcIp)
            self.wsusIp, self.wsusPort = self._extractWsusServerSYSVOL()
        except Exception as e:
            self.logger.error("Error: {}".format(e))
            self.logger.error("Error while looking for WSUS Server in SYSVOL Share.")
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()
        finally:
            try:
                self._closeConnection()
            except:
                pass

        if not self.wsusIp or not self.wsusPort:
            self.logger.error("Error: WSUS-Server-IP not set. Try to specify the WSUS Server manually with --WSUS-Server and -WSUS-Port. Exiting...")
            sys.exit(1)

        return self.wsusIp, self.wsusPort