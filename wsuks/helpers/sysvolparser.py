
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

    def _createSMBConnection(self, domain, username, password, dcIp, kerberos=False, dcName="", lmhash="", nthash="", aesKey=""):
        """Create a SMB connection to the target"""
        # SMB Login would be ready for kerberos or NTLM Hashes Authentication if it is needed
        # TODO: Fix remoteName in SMBConnection if this is a bug
        # TODO: Add Kerberos Authentication
        try:
            if kerberos:
                self.conn = SMBConnection(remoteName=dcName, remoteHost=dcIp, sess_port=445)
            else:
                self.conn = SMBConnection(remoteName=dcIp, remoteHost=dcIp, sess_port=445)

            if kerberos is True:
                self.conn.kerberosLogin(username, password, domain, lmhash, nthash, aesKey, dcIp, useCache=False)
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

        possible_wsus_locations = []

        policies = self.conn.listPath("SYSVOL", f"{self.domain}/Policies/*")
        for policy in policies:
            try:
                self.reg_data = b""
                self.conn.getFile("SYSVOL", f"{self.domain}/Policies/{policy.get_longname()}/Machine/Registry.pol", output_callback)
                reg_pol = RegistryPolicy(self.reg_data).get_policies()
                for pol in reg_pol:
                    if pol["key"] == "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate" and pol["value"] == "WUServer":
                        try:
                            scheme, host, wsusPort = re.search(r"^(https?)://(.+):(\d+)$", pol["data"]).groups()
                            possible_wsus_locations.append({"name": policy.get_shortname(), "scheme": scheme, "host": host, "port": int(wsusPort)})
                        except Exception as e:
                            self.logger.error(f"Could not parse WSUS Policy (error: {e}): {pol}")
            except SessionError as e:
                self.logger.debug(f"Error: {e}")
            except Exception as e:
                self.logger.error(f"Error: {e}")
                if self.logger.level == logging.DEBUG:
                    traceback.print_exc()

        # Check if we found any WSUS Policies
        if not possible_wsus_locations:
            self.logger.error("Error: No WSUS policies found in SYSVOL Share.")
        elif len(possible_wsus_locations) == 1:
            if scheme == "http":
                self.logger.success(f"Found vulnerable WSUS Server using HTTP: {scheme}://{host}:{wsusPort}")
                return host, wsusPort
            elif scheme == "https":
                self.logger.critical(f"Found WSUS Server using HTTPS: {scheme}://{host}:{wsusPort}")
                self.logger.critical("Not vulnerable to WSUS Attack. Exiting...")
                sys.exit(1)
        elif len(possible_wsus_locations) > 1:
            self.logger.warning("Found multiple WSUS Policies, please specify the WSUS Server manually with --WSUS-Server and --WSUS-Port.")
            for policy in possible_wsus_locations:
                self.logger.warning(f"Found WSUS Server Policy '{policy['name']}', target URL: {policy['scheme']}://{policy['host']}:{policy['port']}")

        return None, None

    def findWsusServer(self, domain, username, password, dcIp, kerberos, dcName) -> tuple[str, int]:
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
            if self._createSMBConnection(domain, username, password, dcIp, kerberos, dcName):
                host, self.wsusPort = self._extractWsusServerSYSVOL()

                # Check if host is an IP Address, if not resolve it
                if host and self.wsusPort:
                    try:
                        self.wsusIp = str(ip_address(host))
                    except ValueError:
                        self.logger.debug(f"Host '{host}' is not an IP Address, trying to resolve host.")
                        try:
                            self.wsusIp = socket.gethostbyname(host)
                        except socket.gaierror:
                            self.logger.error(f"Error: Could not resolve host '{host}'.")
        except Exception as e:
            self.logger.error(f"Error while looking for WSUS Server in SYSVOL Share: {e}")
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()
        finally:
            with contextlib.suppress(Exception):
                self.conn.close()

        if not self.wsusIp or not self.wsusPort:
            self.logger.error("Error: WSUS-Server-IP not set. Try to specify the WSUS Server manually with --WSUS-Server and --WSUS-Port. Exiting...")
            sys.exit(1)

        return self.wsusIp, int(self.wsusPort)
