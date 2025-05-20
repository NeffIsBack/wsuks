
import logging
import re
import socket
import sys
import traceback
import contextlib
from impacket.smbconnection import SMBConnection, SessionError
from ipaddress import ip_address
from wsuks.helpers.regpol_parser import RegistryPolicy


class SysvolParser:
    def __init__(self):
        self.logger = logging.getLogger("wsuks")
        self.conn = None
        self.share = "SYSVOL"
        self.wsusIp = None
        self.wsusPort = None  # Default 8530

        # Login info
        self.username = ""
        self.password = ""
        self.dcIp = ""
        self.domain = ""

    def _createSMBConnection(self, domain, username, password, dcIp, kerberos=False, lmhash="", nthash="", aesKey=""):
        """Create a SMB connection to the target"""
        # SMB Login would be ready for kerberos or NTLM Hashes Authentication if it is needed
        # TODO: Fix remoteName in SMBConnection if this is a bug
        # TODO: Add Kerberos Authentication
        try:
            self.conn = SMBConnection(remoteName=dcIp, remoteHost=dcIp, sess_port=445)

            if kerberos is True:
                self.conn.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, dcIp)
            else:
                self.conn.login(username, password, domain, lmhash, nthash)
            if self.conn.isGuestSession() > 0:
                self.logger.debug("GUEST Session Granted")
            else:
                self.logger.debug("USER Session Granted")
            return True
        except Exception as e:
            self.logger.error(f"Error: {e}")
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()
            return False

        return self.conn

    def _extractWsusServerSYSVOL(self):
        def output_callback(data):
            self.reg_data += data

        policies = self.conn.listPath("SYSVOL", f"{self.domain}/Policies/*")
        for policy in policies:
            try:
                self.reg_data = b""
                self.conn.getFile("SYSVOL", f"{self.domain}/Policies/{policy.get_longname()}/Machine/Registry.pol", output_callback)
                reg_pol = RegistryPolicy(self.reg_data).get_policies()
                for pol in reg_pol:
                    if pol["key"] == "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate" and pol["value"] == "WUServer":
                        try:
                            scheme, hostname, wsusPort = re.search(r"^(https?)://(.+):(\d+)$", pol["data"]).groups()
                            if scheme == "http":
                                self.logger.success(f"Found vulnerable WSUS Server using HTTP: {scheme}://{hostname}:{wsusPort}")
                                return hostname, wsusPort
                            elif scheme == "https":
                                self.logger.critical(f"Found WSUS Server using HTTPS: {scheme}://{hostname}:{wsusPort}")
                                self.logger.critical("This is not vulnerable to WSUS Attack. Exiting...")
                                sys.exit(1)
                        except Exception as e:
                            self.logger.error(f"Found WSUS Policy, but could not parse value: {e}")
                            self.logger.error(f"Policy: {pol}")
            except SessionError as e:
                self.logger.debug(f"Error: {e}")
            except Exception as e:
                self.logger.error(f"Error: {e}")
                if self.logger.level == logging.DEBUG:
                    traceback.print_exc()
        return None, None

    def findWsusServer(self, domain, username, password, dcIp) -> tuple[str, int]:
        """
        Get the WSUS server IP address from GPOs of the SYSVOL share

        :param domain: Domain name
        :param username: Username
        :param password: Password
        :param dcIp: Domain Controller IP
        :return: WSUS Server IP and Port
        """
        if not username or not password or not dcIp or not domain:
            self.logger.error("Error: Domain Controller IP, Username, Password and Domain are required to search for WSUS Server in SYSVOL Share. Exiting...")
            sys.exit(1)

        self.username = username
        self.password = password
        self.dcIp = dcIp
        self.domain = domain

        try:
            if self._createSMBConnection(domain, username, password, dcIp):
                hostname, self.wsusPort = self._extractWsusServerSYSVOL()
                # Check if hostname is an IP Address, if not resolve it
                try:
                    self.wsusIp = str(ip_address(hostname))
                except ValueError:
                    self.logger.debug(f"Hostname '{hostname}' is not an IP Address, trying to resolve hostname.")
                    try:
                        self.wsusIp = socket.gethostbyname(hostname)
                    except socket.gaierror:
                        self.logger.error(f"Error: Could not resolve hostname '{hostname}'.")
        except Exception as e:
            self.logger.error(f"Error: {e}")
            self.logger.error("Error while looking for WSUS Server in SYSVOL Share.")
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()
        finally:
            with contextlib.suppress(Exception):
                self.conn.close()

        if not self.wsusIp or not self.wsusPort:
            self.logger.error("Error: WSUS-Server-IP not set. Try to specify the WSUS Server manually with --WSUS-Server and --WSUS-Port. Exiting...")
            sys.exit(1)

        return self.wsusIp, int(self.wsusPort)
