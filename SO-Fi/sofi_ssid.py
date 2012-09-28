'''
SSID Object for SoFI

    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.

'''
from sofi_config import *
import sofi_crypt

def isSofiSSID(SSID):
    if(SSID.find(SSID_PREFIX)==0 and len(SSID)==32):
        return True
    else:
        return False
    
class ssid:
        
    def __init__(self, hashString=None, SSID=None, native=True, private=False, request=True, reply=False, service=0, Comid=0, bitSize=5):
        if((bitSize > 15) and (bitSize < 0)):
            bitSize=5 # Set to default if out of bounds!
        if(SSID == None and hashString != None):
            if(len(hashString)==20):
                self.native = native
                self.service = service
                self.private = private
                self.request = request
                self.reply = reply
                self.bitSize = bitSize
                self.id = Comid
                self.hash = hashString
                self.string = self.toString()
                return
        elif(SSID != None):
            self.fromString(SSID)
            return
        self.native = native
        self.service = service
        self.private = private
        self.request = request
        self.reply = reply
        self.bitSize = bitSize
        self.id = Comid
        self.hash = "00000000000000000000"
        self.string = self.toString()
            
    def fromString(self, SSID):
        """
        Take an SSID String and turn it into and SSID Object.
        """
        self.string = SSID
        SSID = SSID.lstrip(SSID_PREFIX)
        flags = bytearray(self._decode(SSID[:5]))
        self.native = flags[0]&128==128 #Check first Bit of first Byte whether it is 1
        self.private = flags[0]&64==64 #Check second Bit of first Byte for whether it is 1
        self.request = flags[0]&32==32 #Third Bit
        self.reply = flags[0]&16==16 # Fourth Bit
        self.bitSize = flags[0]&15
        self.service = flags[1] #The Service is encoded in the second Byte
        self.id = flags[3]
        self.hash = self._decode(SSID[5:])
        
    def isNative(self):
        return self.native
        
    def isPublic(self):
        return not(self.private) 
        
    def isPrivate(self):
        return self.private
        
    def isRequest(self):
        return self.request
        
    def isReply(self):
        return self.reply
        
    def getID(self):
        return self.id
        
    def getService(self):
        return self.service
    
    def getHash(self):
        return self.hash
    
    def getBitSize(self):
        return self.bitSize
        
    def toString(self):
        self.string = SSID_PREFIX
        flag = chr((self.native<<7) + (self.private<<6) + (self.request<<5) + (self.reply<<4) + (self.bitSize))
        flag = flag + chr(self.service)
        flag = flag + chr(32)
        flag = flag + chr(self.id)
        self.string = self.string + self._encode(flag) + self._encode(self.hash)
        return self.string
    
    def _decode(self, s):
        return sofi_crypt.b85decode(s)
    
    def _encode(self, s):
        return sofi_crypt.b85encode(s)

def test():
    myhash = sofi_crypt.singleHash("hashStringhashString ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    print "Creating SSID Object from Config with with Hash:"
    ssid1 = ssid(hashString=myhash,native=True,private=False,request=True,reply=False,service=1,Comid=255)
    print "SSID: %s" %ssid1.toString()
    print "Service: %s" %ssid1.getService()
    print "Hash: %s" %ssid1.getHash()
    print "ID: %s" %ssid1.getID()
    
    print "Creating SSID Object from SSID String:"
    ssid2 = ssid(SSID=ssid1.toString())
    print "SSID: %s" %ssid2.toString()
    print "Service: %s" %ssid2.getService()
    print "Hash: %s" %ssid2.getHash()
    print "ID: %s" %ssid2.getID()
    
    if(ssid1.toString()==ssid2.toString() and ssid1.getService() == ssid2.getService() and ssid1.getHash() == ssid2.getHash() and ssid1.getID() == ssid2.getID() and ssid1 != ssid2):
        print "SSIDs match! Successful conversion!"
    else:
        print "SSIDs do not match, or are the same Object! FAILURE!"
        
if __name__ == '__main__':
    test()
