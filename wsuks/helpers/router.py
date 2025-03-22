import logging
from scapy.all import get_if_hwaddr
try:
    from nftables import Nftables
except ImportError:
    logger = logging.getLogger("wsuks")
    logger.error("nftables is not installed. Please install nftables to use the Router class. See installation instructions in the README.md.")
    exit(1)


class Router:
    """Takes care of routing ARP spoofed traffic to the local HTTP server."""

    def __init__(self, targetIp, hostIp, wsusIp, wsusPort, interface):
        self.logger = logging.getLogger("wsuks")
        self.isRunning = False
        self.targetIp = targetIp
        self.hostIp = hostIp
        self.hostMac = get_if_hwaddr(interface)
        self.wsusIp = wsusIp
        self.wsusPort = wsusPort
        self.interface = interface
        self.nft = Nftables()
        self.nft.set_json_output(True)

    def start(self):
        """Configure nftables equivalent to the following rules:

        nft 'add table ip wsuks'
        nft 'add chain ip wsuks wsuks-nat { type nat hook prerouting priority dstnat; policy accept; }'
        nft 'add rule ip wsuks wsuks-nat ip saddr <TARGET-IP> tcp dport <WSUKS-PORT> dnat ip to <HOST-IP>'
        """
        self.isRunning = True
        self.logger.info(f"Configure nftables for NATing incoming packages from {self.targetIp} with source {self.wsusIp}:{self.wsusPort} to {self.hostIp}")

        self.nft.cmd("add table ip wsuks")
        self.nft.cmd("add chain ip wsuks wsuks-nat { type nat hook prerouting priority dstnat; policy accept; }")
        self.nft.cmd(f"add rule ip wsuks wsuks-nat ip saddr {self.targetIp} tcp dport {self.wsusPort} dnat ip to {self.hostIp}")

    def stop(self):
        """
        Stop the ARP spoofing process by deleting configured nftables table 'wsuks':

        nft flush table ip wsuks
        nft delete table ip wsuks
        """
        if self.isRunning and self.targetIp:
            self.logger.info("Stop routing: Delete 'wsuks' routing table")
            self.nft.cmd("flush table ip wsuks")
            self.nft.cmd("delete table ip wsuks")
            self.isRunning = False
        else:
            self.logger.error("Router is not running")
