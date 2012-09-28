'''
Created on Jul 5, 2012

    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.
'''
import sys
from mom.codec import base85
import pbkdf2
import hashlib
import binascii
import random
from operator import xor
from itertools import izip, cycle

from sofi_timing import *
from sofi_config import *

@print_timing
def randomKey(randSize=20):
    try:
        randgen = random.SystemRandom()
    except:
        randgen = random
    b = bytearray()
    for _i in range(randSize):
        b.append(randgen.randint(0,255))
        
    return bytearray(hashlib.sha1("%s" %b).digest())
    
def xorDecode(data,key):
    """
    XORs the given data with the given Key.
    """
    return xorCode(data,key)
    
def xorEncode(data,key):
    """
    XORs the given data with the given Key.
    """
    return xorCode(data,key)

def xorCode(data,key):
    """
    XORs the given data with the given Key.
    """
    data = str(data)
    key = str(key)
    return ''.join(chr(ord(x) ^ ord(y)) for (x,y) in izip(data, cycle(key)))

@print_timing
def trippleHash(hashString):
    """
    Create a hashchain of length 3 for the input hashString and return it as a list.
    """
    #Old implementation:
    #_hashlist = []
    #for _i in xrange(3):
    #    hashString = hashlib.sha1(hashString).digest()
    #    _hashlist.append(hashString)
    
    # This seems to be a bit faster:
    hash0 = hashlib.sha1(hashString).digest()
    hash1 = hashlib.sha1(hash0).digest()
    hash2 = hashlib.sha1(hash1).digest()
    _hashlist = [hash0,hash1,hash2]
    
    return _hashlist

def singleHash(hashString):
    """
    Hash the given String
    """
    return hashlib.sha1(hashString).digest()

def Hash(hashString):
    """
    Hash the given String
    """
    return singleHash(hashString)

@print_timing        
def computePSK(ssid, key):
    """
    Compute the PSK for the given SSID and Key.
    Returns None if the Key does not have the necessary length.
    """
    if((len(key)>=8) and (len(key)<=63)):
        if(QUICK_MODE):
            return pbkdf2.pbkdf2_bin(key, ssid, 256, 32)
        else:
            return pbkdf2.pbkdf2_bin(key, ssid, 4096, 32)
    else:
        return None

@print_timing    
def computePSK_hex(ssid, key):
    """
    Compute the PSK for the given SSID and Key.
    Will return None if the key does not have the necessary length.
    """
    if((len(key)>=8) and (len(key)<=63)):
        if(QUICK_MODE):
            return pbkdf2.pbkdf2_hex(key, ssid, 256, 32)
        else:
            return pbkdf2.pbkdf2_hex(key, ssid, 4096, 32)
    else:
        return None
    
def unhex(mystring):
    """
    Takes a Hex String and returns a Binary String.
    """
    mystring = str(mystring)
    return binascii.unhexlify(mystring)
    
def hex(mystring):
    """
    Takes a binary String and returns a Hex String.
    """
    mystring = bytearray(mystring)
    return binascii.hexlify(mystring)

def sanitize(s):
    """
    Return a sanitized version of the given string.
    """

    res = []
    for c in list(s):
        # characters that are converted to underscores
        sanitized_as_underscore = [" ", "-", "_", "."]

        # have at most one consecutive underscore in the string
        if len(res) > 0 and res[-1] == '_' and c in sanitized_as_underscore:
            continue
        elif c in sanitized_as_underscore:
            res.append('_')
        # skip non-ASCII characters such as umlauts
        elif ord(c) >= 128:
            continue
        else:
            res.append(c.lower())

    return "".join(res)

def b85decode(s):
    """
    Decode the given base85 string.
     - Adds required Tags.
    """
    #return ascii85.b85decode("<~%s~>" %s)
    return base85.b85decode("%s" %s)

def b85encode(s):
    """
    Encode the given String to Base85.
    """
    #return ascii85.b85encode(s,False,False)
    return base85.b85encode(s)

def crc16(s):
    crcValue=0x0000
    crc16tab = (0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280,
    0xC241, 0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481,
    0x0440, 0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81,
    0x0E40, 0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880,
    0xC841, 0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81,
    0x1A40, 0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80,
    0xDC41, 0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680,
    0xD641, 0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081,
    0x1040, 0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281,
    0x3240, 0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480,
    0xF441, 0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80,
    0xFE41, 0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881,
    0x3840, 0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80,
    0xEA41, 0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81,
    0x2C40, 0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681,
    0x2640, 0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080,
    0xE041, 0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281,
    0x6240, 0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480,
    0xA441, 0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80,
    0xAE41, 0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881,
    0x6840, 0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80,
    0xBA41, 0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81,
    0x7C40, 0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681,
    0x7640, 0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080,
    0xB041, 0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280,
    0x9241, 0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481,
    0x5440, 0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81,
    0x5E40, 0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880,
    0x9841, 0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81,
    0x4A40, 0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80,
    0x8C41, 0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680,
    0x8641, 0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081,
    0x4040)
    for ch in s:
        tmp=crcValue^(ord(ch))
        crcValue=(crcValue>> 8)^crc16tab[(tmp & 0xff)]
    return crcValue

def test():
    logging.basicConfig( level=logging.DEBUG)
    print "Random key: %s" %randomKey()
    print "PSK: %s" %computePSK_hex('#;[/qJJGQI#b[1<s%MK8"VmJmK@BKo`/','4f044fdf0d72a8e5292495fd2b4')
    print "ASCII85: %s" %b85encode("This is a stupid test.")
    

def eval_hashes():
    import platform
    import csv
    import time
    writer = csv.writer(open("hashing_" + platform.system() +"_"+ platform.node() +"_"+ platform.release()+ "_" + platform.processor() + ".csv","ab"))
    no_samples = 1000
    
    writer.writerow([1])
    for k in xrange(0,6):
        resultlist = [10**k]
        for _j in xrange(no_samples):
            key = "%s" %randomKey()
            start_time = time.time()
            for _l in xrange(10**k):
                _hashString = hashlib.sha1(key).digest()
            end_time = time.time()
            resultlist.append(end_time - start_time)
        writer.writerow(resultlist)

    writer.writerow([2])
    for k in xrange(0,6):
        resultlist = [10**k]
        for _j in xrange(no_samples):
            key = "%s" %randomKey()
            start_time = time.time()
            for _l in xrange(10**k):
                _hashString = hashlib.sha1(key).digest()
                _hashString = hashlib.sha1("%s" %_hashString).digest()
            end_time = time.time()
            resultlist.append(end_time - start_time)
        writer.writerow(resultlist)

    writer.writerow([3])
    for k in xrange(0,6):
        resultlist = [10**k]
        for _j in xrange(no_samples):
            key = "%s" %randomKey()
            start_time = time.time()
            for _l in xrange(10**k):
                _hashString = hashlib.sha1(key).digest()
                _hashString = hashlib.sha1("%s"%_hashString).digest()
                _hashString = hashlib.sha1("%s"%_hashString).digest()
            end_time = time.time()
            resultlist.append(end_time - start_time)
        writer.writerow(resultlist)
         
def eval_psk():
    import platform
    import csv
    import time
    
        
    writer = csv.writer(open("PSK_" + platform.system() +"_"+ platform.node() +"_"+ platform.release()+ "_" + platform.processor() + ".csv","ab"))
    sample_no = 1000
    result_full = [4096]
    result_quick = [256]
    for _i in xrange(sample_no):
        ssid ="%s" %randomKey()
        key = "%s" %randomKey()
        start_time = time.time()
        computePSK(ssid, key, quick = True)
        end_time = time.time()
        result_quick.append(end_time-start_time)
        start_time = time.time()
        computePSK(ssid, key, quick = False)
        end_time = time.time()
        result_full.append(end_time-start_time)
    
    writer.writerow(result_quick)
    writer.writerow(result_full)
    
    

if __name__ == "__main__":
    eval_hashes()
    eval_psk()
    #test()
