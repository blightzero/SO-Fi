#!/usr/bin/python
'''
Created on Aug 3, 2012

    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.
'''
import fcntl
import socket
import struct
import binascii
import random
import os
import subprocess
import logging

def getHwAddr(ifname):
    """
    Get the MAC Address of the Interface Name given:
    example: getHwAddr('eth0')
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return sanitizeMac(''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1])


def getHwAddrBin(ifname):
    """
    Get the MAC Address of the Interface Name given:
    example: getHwAddr('eth0')
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return info[18:24]
   
def isRoot():
    """Verifies if the current user is root"""
    return os.getuid() & os.getgid() == 0

def setLinuxMAC(device,mac):
    """Sets the new mac for device, in a Linux system"""
    try:
        subprocess.check_call(["ifconfig","%s" % device, "down"])
        subprocess.check_call(["ifconfig","%s" % device, "hw", "ether","%s" % mac])
        subprocess.check_call(["ifconfig","%s" % device, "up"])
    except:
        return False
    return True
    
def setAndroidMac(device,mac):
    """Sets the new mac for device, in a Linux system"""
    subprocess.check_call(["ifconfig","%s" % device, "up"])
    subprocess.check_call(["ifconfig","%s" % device, "hw", "ether","%s" % mac])

def randomMacAddress():
    """Randomly generates the missing bytes of the MAC address started by prefix"""
    mac=[]
    for _ in xrange(6):
        mac.append(random.randint(0x00, 0x7f))
    mac[0]=mac[0]&0xFE #round to even number the first byte for unicast address!
    return sanitizeMac(':'.join('%02x' % x for x in mac))

def sanitizeMac(mac):
    temp = mac.replace(":", ":").replace("-", ":").replace(".", ":").lower()
    temp = temp.split(":")
    temp = ''.join(['%02s' %chars for chars in temp])
    temp = temp.replace(" ","0")
    return temp[:2] + ":" + ":".join([temp[i] + temp[i+1] for i in range(2,12,2)])

def convertMacString(octet):
    """
    This Function converts a binary mac address to a hexadecimal string representation
    """
    mac = [binascii.b2a_hex(x) for x in list(octet)]
    return sanitizeMac(":".join(mac))

def convertMacBin(mac):
    """
    This Function converts a mac string representation into a binary mac address
    """
    mac = sanitizeMac(mac)
    mac = mac.split(":")
    mac = ''.join([binascii.unhexlify(x) for x in mac])
    return mac

class randomMAC:
    MAC_list = []
    pos = 0
    maxNum = 10
    
    def __init__(self,maxNum=10):
        self.maxNum = maxNum
        logging.info("Generating %s random MAC addresses." %maxNum)
        for _ in xrange(maxNum):
            mac = bytearray()
            for _ in xrange(6):
                mac.append(random.randint(0x00, 0x7f))
            mac[0]=mac[0]&0xFE #round to even number the first byte for unicast address!
            self.MAC_list.append(mac)
    
    def getRandomMacBin(self):
        ret = self.MAC_list[self.pos]
        self.pos = (self.pos+1) % self.maxNum
        return ret
    
    def getRandomMacString(self):
        return convertMacString(self.getRandomMacBin())
    
