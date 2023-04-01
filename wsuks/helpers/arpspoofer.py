#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import scapy

class ArpSpoofer:
    def __init__(self):
        self.logger = logging.getLogger()

    def getMac(ip):
        arp_request = scapy.ARP(pdst = ip)
        broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
        return answered_list[0][1].hwsrc

    def spoof(self, targetIp, spoofIp):
        pass

    def restore(self, targetIp, spoofIp):
        pass