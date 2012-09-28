"""
Functionality of the So-Fi client.

    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.

"""

import os
import stat
import sys
import tempfile
import threading
import time
import random
import logging
import subprocess

from sofi_config import *
import sofi_wpa_supplicant
import sofi_ssid
import sofi_puzzle
import sofi_crypt
import sofi_iftools

try:
    import PWIFI_COMMON as COMMON
except ImportError:
    print "Missing pwifi imports. Call 'make python-imports' in pwifi dir."
    sys.exit(1)


def create_trigger(pid, prefix="pwifi_trigger_", suffix=".sh", disconnect=False):
    """
    Create a temporary shellscript that sends a USR1 signal to
    the given pid when it is called. If the 'disconnect' flag is set
    it sends USR2 to the given pid when the connection is disestablished.

    Reference to Temporary file object is returned.
    Caller is responsible for removing the temporary file.
    """

    trigger = (
    """
    #!/bin/sh

    # Trigger a signal when the association is established.
    # This script is supposed to be called as an action script for wpa_cli.
    # This script is generated automatically so do not modify it.

    CMD=$2

    if [ "$CMD" = "CONNECTED" ]; then
        kill -s USR1 %d
    fi

    """ % pid)

    if disconnect:
        trigger += (
    """
    if [ "$CMD" = "DISCONNECTED" ]; then
        kill -s USR2 %d
    fi
    """ % pid)

    with tempfile.NamedTemporaryFile(prefix=prefix, suffix=suffix,
                                     delete=False) as f:
        f.write(trigger)
        os.chmod(f.name, stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH |
                 stat.S_IRUSR | stat.S_IWUSR)
        return f

class Client():
    """
    pwifi client responsible for dealing with specific requests like
    selecting and connecting to groups or getting a specific file.
    """

    # When connecting to a pwifi network we initially provide some bogus password
    # which will not actually be used by wpa_supplicant.
    _pwd = "boguspassword"
    wpa = None
    
    def __init__(self):
        global WIFI_INTERFACE
        self.state = IDLE
        self.timeoutTimer = None
        self.nId = None
        self.ComId = 0
        self.request = None
        self.ssid = None
        self.ie = None
        self.lastScan = None
        self.connectedBSSID="0:0:0:0:0:0"
        self.wpa = sofi_wpa_supplicant.Wpa_supplicant_controller()
        
        WIFI_INTERFACE = self._get_wifi_interface()
        logging.info("Using Wifi interface: %s" %WIFI_INTERFACE)
        logging.info("Initializing Scan thread.")
        self.eventThread = threading.Thread(target=self._get_events)
        self.eventThread.daemon = True
        self.eventThread.start()
        
    def _eval_events(self,event):
        event = event[3:].split()
        if(event[0]=="CTRL-EVENT-BSS-ADDED"):
            apList = self.wpa.wpa_supplicant_get_scan()
            apList = apList.split('\n')
            apList = apList[1:-1]
            for line in apList:
                item = line.split()
                if(item[0]==event[2]):
                    if(len(item)<5):
                        logging.error("Strange AP added: %s" %item)
                        return
                    logging.info("AP added: %s with SSID: %s" %(item[0],item[4]))                    
                    if(sofi_ssid.isSofiSSID(item[4]) and (self.state == WAITING_FOR_RESPONSE or self.state == ANSWERED_PUZZLE)):
                        ssid = sofi_ssid.ssid(SSID=item[4])
                        if(ssid.getID()==self.ComId):
                            logging.info("Received matching response with ComID: %s" %self.ComId)
                            #This is a reply to a request we sent.
                            if(self.state == WAITING_FOR_RESPONSE):
                                logging.info("Waited for response and response received!")
                                self._stop_timeout()
                                self.endScanDiscoverTime = time.time()
                                solution = self._start_puzzle(ssid)
                                logging.info("Puzzle solved and setting up answer!")
                                self.wpa.wpa_supplicant_remove_net(self.nId)
                                self._start_connect(solution, service=ssid.getService(), private=ssid.isPrivate(), password=self.request[0], bitSize=ssid.getBitSize())
                            if(self.state == ANSWERED_PUZZLE):
                                logging.info("Answered puzzle and response received: connecting to Network!")

        elif(event[0]=="CTRL-EVENT-CONNECTED"):
            logging.debug("Connected event received: %s" %event)
            if(event[7][4:]==self.nId):
                if(self.state != CONNECTED):
                    logging.info("Connected to network!")
                    self._stop_timeout()
                    self.connectedBSSID = event[4]
                    self.ie = self._get_ie(self.connectedBSSID,ForceSSID=True)
                    self.end_time = time.time()
                    self.endConnectDiscover = self.end_time
                    if(IS_EVAL):
                        self.state = CONNECTED
                        return
                    while(self.ie == None):
                        time.sleep(DELAY)
                        self.lastScan = self.wpa.wpa_supplicant_get_scan()
                        self.ie = self._get_ie(self.connectedBSSID,ForceSSID=True)
                    logging.info("Received IE: %s" %self.ie)
                    ie_ssid,ie_sofi = self._parse_ie(self.ie)
                    logging.info("Parsed IE: SSID: %s  So-Fi: %s" %(ie_ssid,ie_sofi))
                    self._eval_sofi_ie(ie_sofi)
                    self.state = CONNECTED
                else:
                    logging.info("Reauth to Network with Id: %s" %self.nId)
            else:
                self.ie = self._get_ie(event[4],ForceSSID=False)
                logging.info("Received IE: %s" %self.ie)
        elif(event[0]=="CTRL-EVENT-DISCONNECTED"):
            logging.debug("Disconnect event received: %s" %event)
            if(self.state == CONNECTED):
                bssid = event[1][6:]
                logging.info("Disconnected from Network with BBSID: %s" %bssid)
                if(bssid == self.connectedBSSID):
                    logging.info("Disconnected from So-Fi Network!")
                    self.wpa.wpa_supplicant_remove_net(self.nId)
        elif(event[0]=="CTRL-EVENT-SCAN-RESULTS"):
            self.lastScan = self.wpa.wpa_supplicant_get_scan()      
        else:
            logging.debug(event)

    def _remove_old_nets(self):
        """ 
        
        Removing old networks in order to clean up the network list.
        Speeds up the scanning and looks nicer.
        """
        networks = self.wpa.wpa_supplicant_list_networks()
        netlist = networks.split('\n')
        for item in netlist:
            item = item.split()
            if(len(item)<2):
                break
            if(sofi_ssid.isSofiSSID(item[1])):
                self.wpa.wpa_supplicant_remove_net(item[0])

    def _get_wifi_interface(self):
        """
        Get the used wifi interface.
        Returns the first Item in the Interface list!
        """
        ifs = self.wpa.wpa_supplicant_interfaces()
        if_list = ifs.split('\n')
        
        return if_list[0]
    
    def _get_ie(self,bssid,ForceSSID=False):
        """
        Get the Information Elements from a Network with specified BSSID
        """
        
        if(self.lastScan != None):
            scan_list = self.lastScan.split('\n')
            for i,line in enumerate(scan_list):
                items = line.split()
                if(len(items)<1):
                    return None
                if(items[0] == bssid):
                    if(ForceSSID):
                        if(len(items)<5):
                            continue
                        if(items[4]==self.ssid):
                            return self._get_bss_ie(i-1)
                    else:
                        return self._get_bss_ie(i-1)
        else:
            return None
   
    def _parse_ie(self,ie):
        """
        Parse the Information Elements received from a BSSID.
        """
        if(ie == None):
            return None,None
        ie = sofi_crypt.unhex(ie)
        pos = 0
        ie_map = {}
        
        while ((pos+1) < len(ie)):
            pos +=1
            length = ord(ie[pos])
            pos +=1
            ie_map[ord(ie[pos-2])]=ie[pos:(pos+length)]
            pos +=length

        if(COMMON.PWIFI_EID in ie_map):
            sofi = ie_map[COMMON.PWIFI_EID]        
            pos = 0
            sofi_ie_map = {}
            while ((pos+1) < len(sofi)):
                pos +=1
                length = ord(sofi[pos])
                pos +=1
                sofi_ie_map[ord(sofi[pos-2])]= sofi[pos:(pos+length)]
                pos +=length
            
            return ie_map,sofi_ie_map
        else:
            return ie_map,None
    
    def _eval_sofi_ie(self,ie):
        """
        Evaluate the parsed Information Elements. 
        """
        logging.info("Evaluating So-Fi Information Elements.")
        if(COMMON.PWIFI_EID_IP in ie):
            subprocess.call(["sudo", "ifconfig", WIFI_INTERFACE, ie[COMMON.PWIFI_EID_IP]])
            logging.info("Setting IP to: %s" %ie[COMMON.PWIFI_EID_IP])
        if(COMMON.PWIFI_EID_URL in ie):
            url = "%s/index?address=%s&request=%s&solution=%s" %(ie[COMMON.PWIFI_EID_URL],sofi_crypt.hex(sofi_iftools.getHwAddrBin(WIFI_INTERFACE)),sofi_crypt.hex(self.request[0]),sofi_crypt.hex(self.solution))
            subprocess.Popen(["xdg-open", url])
            logging.info("Opening URL: %s" %url)

    def _get_bss_ie(self,idx):
        """
        Get the BSS Information for a specified Scan-list Id and return the IE.
        """
        bss = self._get_bss(idx)
        lines = bss.split('\n')
        for line in lines:
            item = line.split('=')
            if(item[0]=="ie"):
                ie = item[1]
        return ie
    
    def _get_bss(self,idx):
        """
        Get more Information about a certain BSS
        Idx relates to the Index in the last Scan from WPA supplicant.
        """
        return self.wpa.wpa_supplicant_get_bss(idx)
    
    def _get_events(self):
        """
        Main thread to receive and evaluate the Events received from the wpa_supplicant.
        """
        print "Starting to receive events!!!!"
        logging.info("Starting to received events from WPA Supplicant with delay: %.03f." %DELAY)
        while True:
            time.sleep(DELAY)
            if(True):
                if(self.wpa.wpa_supplicant_is_running()):
                    while(self.wpa.wpa_supplicant_event_pending()):
                        self._eval_events(self.wpa.wpa_supplicant_get_event())
            else:
                logging.error("Failed to get Events from WPA Supplicant.") # %sys.exc_info())        

    def _start_puzzle(self,ssid):
        """
        Handle the puzzle.
        Read puzzle from the SSID encrypted with first PreImage, return Puzzle encrypted with first PreImage
        """
        self.startPuzzleTime = time.time()
        bitSize = ssid.getBitSize()
        if(bitSize == 0): # No Puzzle required! Connect to network!
            logging.info("Required Puzzle Size is 0! Not solving Puzzle!")
            return self.request[1]
        else:
            recvhash = bytearray(ssid.getHash()) # received "Hash"
            logging.debug("Received Hash: %s length: %s" %(recvhash,len(recvhash)))
            hash2 = bytearray(self.request[1]) # expected Answer
            logging.debug("Expected hash: %s length: %s" %(hash2,len(hash2)))
            puzzle = sofi_crypt.xorDecode(recvhash, hash2) # decode the received Hash with the expected Hash, this gives us the puzzle.
            logging.debug("Puzzle received: %s with length: %s" %(puzzle,len(puzzle)))
            p = sofi_puzzle.mk_preimage_puzzle()
            start = time.clock()
            solution = p.solvePuzzleS(puzzle,bitSize=bitSize) # Solve the received Puzzle
            self.solution = solution
            logging.debug("Puzzle solved in %.06f seconds." %(time.clock()-start))
            logging.debug("Calculated Puzzle Solution: %s" %solution)
            solEnc = sofi_crypt.xorDecode(solution, hash2) # encode the solution with the expected Hash. This is the final ssid.
            logging.debug("Final search Hash: %s" %solEnc)
            self.endPuzzleTime = time.time()
            return solEnc
        
    def _timeout(self):
        if(self.state == IDLE):
            self.state = IDLE
            #Nothing to do here
        elif(self.state == WAITING_FOR_RESPONSE):
            self.state = IDLE
            self.wpa.wpa_supplicant_remove_net(self.nId) #Remove the Search-Network
            logging.info("Nothing was found in %i seconds." %CLIENT_TIMEOUT)
        elif(self.state == RECEIVED_RESPONSE):
            # This is actually kind of bad, we received a response, but did not answer the puzzle yet...
            # We are currently computing the puzzle!
            self.state = RECEIVED_RESPONSE
            self.wpa.wpa_supplicant_remove_net(self.nId)
            logging.info("Timed out after receiving response!") 
        elif(self.state == ANSWERED_PUZZLE):
            self.state = IDLE # we send a Puzzle answer but we did not receive a response
            self.wpa.wpa_supplicant_remove_net(self.nId) #Remove the Search-Network
            logging.error("Connecting to Network failed after %i seconds." %CLIENT_TIMEOUT)
        elif(self.state == CONNECTED):
            self.state = CONNECTED # Keep the State until we reset.
        self.timeoutTimer = None
    
    def _start_timeout(self):
        if(self.timeoutTimer == None):
            self.timeoutTimer = threading.Timer(CLIENT_TIMEOUT,self._timeout)
            self.timeoutTimer.start()
        elif(self.timeoutTimer.isAlive()):
            self.timeoutTimer.cancel()
            self.timeoutTimer = threading.Timer(CLIENT_TIMEOUT,self._timeout)
            self.timeoutTimer.start()
        
    def _stop_timeout(self):
        if(self.timeoutTimer != None):
            if(self.timeoutTimer.isAlive()):
                self.timeoutTimer.cancel()
            self.timeoutTimer = None
    
    def _timerIsActive(self):
        return (self.timeoutTimer.isAlive())
    
    def _sanitize(self, s):
        """
        Return a sanitized version of the given string.
        """
        return sofi_crypt.sanitize(s)
    
    def _trippleHash(self, hashString):
        """
        Create a hashchain of length 3 for the input hashString and return it as a list.
        """
        return sofi_crypt.trippleHash(hashString)
    
    def _start_search(self, target="NOTHING",service=0,private=False,password=None,bitSize=5):
        """
        Search the specified target, ie. do a scan through wpa_supplicant.
        """
        self.startbuildScanTime = time.time()
        if(self.state == IDLE or self.state == CONNECTED):
            self._remove_old_nets()
            if(private==False):
                self.request = self._trippleHash(self._sanitize(target))
                logging.info("Publicly searching for: "+ target)
            else:
                logging.debug("Privately searching for: %s with password: %s" %(target ,password))
                if(password != None):
                    logging.info("Privately searching for: %s" %target)
                    self.request = self._trippleHash(self._sanitize(target))
                    self.request[2] = sofi_crypt.xorDecode(self.request[2],password)
                    self.request[1] = sofi_crypt.xorDecode(self.request[1],password)
                    self.request[0] = sofi_crypt.xorDecode(self.request[0],password)
                    #Encrypt Hash with Secret
                    #Set MAC known to requested User FIXME in future VERSION
                else:
                    logging.error("No Password specified in private search!")
            
            self.ComId = random.randint(0,255)
            self.start_time = time.time()
            ssid = sofi_ssid.ssid(hashString=self.request[2],private=private,request=True,service=service,Comid=self.ComId)
            self.nId = self.wpa.wpa_supplicant_connect(ssid.toString(), pwd=None)
            self.state = WAITING_FOR_RESPONSE
            self._start_timeout()
            self.endbuildScanTime = time.time()
            self.startScanDiscoverTime = time.time()
            return True
        else:
            logging.info("Already searching for another file. Please wait for timeout...")
            return False
    
    def _start_connect(self,target,service=0,private=False,password=None,bitSize=5):
        """
        Get the specified target, ie. establish a connection through wpa_supplicant.
        """
        self.startbuildConnectTime = time.time()
        if(self.state == WAITING_FOR_RESPONSE):            
            ssid = sofi_ssid.ssid(hashString=target,private=private,request=True,reply=True,service=service,Comid=self.ComId,bitSize=bitSize)
            self.ssid = ssid.toString()
            passwd = sofi_crypt.computePSK_hex(ssid.toString(),password)
            logging.info("Connecting to Network with WPA Key: %s" %passwd)
            self.nId = self.wpa.wpa_supplicant_connect(self.ssid, pwd=passwd)
            self.state = ANSWERED_PUZZLE
            self._start_timeout()
            self.endbuildConnectTime = time.time()
            self.startConnectDiscover = time.time()
            return True
        else:
            logging.info("Already searching for another file. Please wait for timeout...")
            return False

    def _simple_connect(self, target, password):
        logging.info("Connecting to Network with WPA Key: %s" %password)
        self.nId = self.wpa.wpa_supplicant_connect(self.ssid, pwd=password)


    def handle_get(self, target):
        """
        Get the specified file.
        """
        return self._start_search(target,service=2,private=False)
    
    def handle_private_get(self, target, key):
        """
        Get the specified file for the specified key.
        """
        return self._start_search(target,service=2,private=True,password=key)
        
    def handle_group(self, target, password):
        """
        Establish a connection with a group network.
        """
        return self._start_search(target=target,service=1,private=False,password=password)
        

    def handle_people_search(self, target):
        """
        Establish a connection with the specified person.
        """
        return self._start_search(target=target,service=3,private=False)

        
    def handle_get_status(self):
        """
        Get the Status of the WPA Supplicant.
        """
        return self.wpa.wpa_supplicant_get_status()
    
    def handle_bss(self,target):
        """
        Get Detailed BSS Info for idx or bssid.
        """
        return self.wpa.wpa_supplicant_get_bss(target)
        
    def handle_disconnect(self):
        """
        Disconnect from the Network.
        """
        self._stop_timeout()
        if(self.nId != None):
            self.wpa.wpa_supplicant_remove_net(self.nId)
            self.nId=None
        self.wpa.wpa_supplicant_disconnect()
        self.state = IDLE
    
    def handle_reconnect(self):
        """
        Reconnect to the currently connected network.
        """
        return self.wpa.wpa_supplicant_reconnect()
    
    def handle_start(self):
        """
        Start the WPA Supplicant
        """
        return self.wpa.start_wpa_supplicant()
        
    def handle_stop(self):
        """
        Stop the WPA Supplicant
        """
        return self.wpa.stop_wpa_supplicant()
    
    def handle_get_scan(self):
        """
        Get the last Scan from the WPA Supplicant.
        """
        return self.lastScan
    
    def handle_scan(self):
        """
        Initiate a new Active Scan on the WPA Supplicant
        """
        return self.wpa.wpa_supplicant_scan()
    
    def handle_get_interfaces(self):
        """
        Get the list of configured Interfaces from the wpa_supplicant.
        """
        return self.wpa.wpa_supplicant_interfaces()
    
    def handle_get_mac(self):
        """
        Get the current MAC Address
        """
        return sofi_iftools.getHwAddr(WIFI_INTERFACE)
    
    def handle_set_mac(self,mac):
        """
        Set the MAC Address of the Wifi Device
        """
        if(sofi_iftools.isRoot()):
            return sofi_iftools.setLinuxMAC(WIFI_INTERFACE, sofi_iftools.sanitizeMac(mac))
        else:
            return False
    
    def handle_ie(self, bssid):
        """
        Get the IE for the following bssid.
        """
        return self._get_ie(bssid, ForceSSID=False)
    
    def handle_connect(self, target):
        """
        Establish connection with a pwifi network.
        The given target string is the users id or network ID which the
        responder may choose to ignore or use as a means of identifying
        the connecting user.
        """
        return self._start_search(target=target,service=0,private=False,password=None)
    
    def handle_list_networks(self):
        """
        Get the list of Networks Configured in WPA_Supplicant.
        """
        return self.wpa.wpa_supplicant_list_networks()

    def handle_remove_net(self,nId):
        """
        Remove Network with ID nId
        """
        return self.wpa.wpa_supplicant_remove_net(nId)
    
    
def main():
    import time
    import platform
    import csv
    
    logging.basicConfig(filename='plain_sofi_eval.log',level=logging.DEBUG, datefmt='%d.%m %H:%M:%S')
    logging.info('Started!')
    
    SSID = "SO-Fi"
    SEARCH_STRING = "istanbul"
    #WPA_KEY = None # No WPA!
    #WPA_KEY = sofi_crypt.computePSK_hex(SSID,"Anipuvod46") #WPA
    #WPA_KEY = "thisisSparta"
    sample_no = 100
    retry = 30 #No of seconds to wait for a successful connect.
    FILENAME="sofi_connect"
    if(not WPA_OFF):
        FILENAME = FILENAME + "_wpa_"
    if(QUICK_MODE):
        FILENAME = FILENAME + "256_"
    else:
        FILENAME = FILENAME + "4096_"
    writer = csv.writer(open(FILENAME + "%s_" %SSID + platform.system() +"_"+ platform.node() +"_"+ platform.release()+ "_" + platform.processor() + ".csv","ab"))
    
    client = Client()


    client.start_time = 0.0
    client.end_time = 0.0
    client.startbuildScanTime = 0.0
    client.endbuildScanTime = 0.0
    client.startScanDiscoverTime = 0.0
    client.endScanDiscoverTime = 0.0
    client.startPuzzleTime = 0.0
    client.endPuzzleTime = 0.0
    client.startbuildConnectTime = 0.0
    client.endbuildConnectTime = 0.0
    client.startConnectDiscover = 0.0
    client.endConnectDiscover = 0.0
    
    #IS_EVAL = True 
    result_list = ["%s" %SSID]
    buildScan_list = ["Build Scan"]
    scanDiscover_list = ["Scan Discovery"]
    Puzzle_list = ["Solve Puzzle"]
    buildConnectWPA_list = ["Build Connect (WPA)"]
    connectDiscover_list = ["Connect"]
    for _i in xrange(sample_no):
        
        client.start_time = 0.0
        client.end_time = 0.0
        client.handle_remove_net(client.nId)
        client.handle_disconnect()
        time.sleep(1)
        client.handle_connect(SEARCH_STRING)
        for _j in xrange(retry):
            time.sleep(1)
            if(client.state == CONNECTED):
                connect_time = client.end_time - client.start_time
                result_list.append(connect_time)
                buildScan_list.append(client.endbuildScanTime - client.startbuildScanTime)
                scanDiscover_list.append(client.endScanDiscoverTime - client.startScanDiscoverTime)
                Puzzle_list.append(client.endPuzzleTime - client.startPuzzleTime)
                buildConnectWPA_list.append(client.endbuildConnectTime - client.startbuildConnectTime)
                connectDiscover_list.append(client.endConnectDiscover - client.startConnectDiscover)
                
                logging.info("Successfully connected. Sample: %s in %s seconds" %(_i, connect_time))
                break


    writer.writerow(result_list)
    writer.writerow(buildScan_list)
    writer.writerow(scanDiscover_list)
    writer.writerow(Puzzle_list)
    writer.writerow(buildConnectWPA_list)
    writer.writerow(connectDiscover_list)
    
if __name__ == "__main__":
    
    main()


