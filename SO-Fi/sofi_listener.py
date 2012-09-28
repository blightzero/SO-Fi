#!/usr/bin/env python
"""
The So-Fi Hostlistener. It acts upon incoming service requests from
hostapd, stores Client States and provides Puzzles.

    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.

"""

import os
import signal
import select
import socket
import subprocess
import struct
import sys
import threading
import logging

from sofi_config import *
from sofi_db import *
import sofi_crypt
import sofi_db
import sofi_ssid
import sofi_puzzle
import sofi_iftools
import sofi_web
import pwifi_dnsmasq
from sofi_timing import *

try:
    import PWIFI_COMMON as COMMON
    import PWIFI_IPC as IPC
except ImportError:
    print "Missing pwifi imports. Call 'make python-imports' in pwifi dir."
    sys.exit(1)


class State():
    '''
    State of a Connection attempt by a Client
    '''
    def __init__(self,address="0:0:0:0:0:0"):
            self.address=address
            self.SA = None
            self.DataItems = None
            if(NO_PUZZLE):
                self.bitSize = 0
            else:
                self.bitSize = 10
            self.Puzzle = None
            self.PuzzleSolution = None
            self.PuzzleSolved = False
            self.ComId = 0
            self.lastSSID = None
            self.State = REQUEST
            self.timeoutTimer = None
            self.start_timeout()
            self.lastReply = IPC.PWIFI_IPC_NACK
            
    def _timeout(self):
        if(self.State == REQUEST):
            self.State = FAILED
            #Nothing to do here
        elif(self.State == PUZZLE_SEND):
            self.State = FAILED
            logging.info("Puzzle was not solved in %0.3f seconds" %LISTENER_TIMEOUT)
        elif(self.State == PUZZLE_SOLVED):
            # This is bad, the Puzzle was solved, but the client did not connect.
            self.State = CONNECTED
        elif(self.State == FAILED):
            self.State = FAILED # FAILED to Connect
        elif(self.State == CONNECTED):
            self.State = CONNECTED # Keep the State until we reset.
        
        if(self.State==FAILED):
            self.address = "0:0:0:0:0:0"
            self.SA = None
            self.DataItems = None
            self.Puzzle = None
            self.PuzzleSolution = None
            self.PuzzleSolved = False 
            self.lastSSID = None
        self.timeoutTimer = None
    
    def start_timeout(self):
        if(self.timeoutTimer == None):
            self.timeoutTimer = threading.Timer(LISTENER_TIMEOUT,self._timeout)
            self.timeoutTimer.start()
        elif(self.timeoutTimer.isAlive()):
            self.timeoutTimer.cancel()
            self.timeoutTimer = threading.Timer(LISTENER_TIMEOUT,self._timeout)
            self.timeoutTimer.start()
        
    def stop_timeout(self):
        if(self.timeoutTimer != None):
            if(self.timeoutTimer.isAlive()):
                self.timeoutTimer.cancel()
            self.timeoutTimer = None
    
    def timerIsActive(self):
        return (self.timeoutTimer.isAlive())


class Listener:
    """
    All listener functionality such as checking for supported services,
    starting services and providing service info in Information Elements.
    """
    def __init__(self, database, statelist, puzzler):
        self.database = database
        self.statelist = statelist
        self.puzzler = puzzler
        self.stateIndex = {}
        self.stateSSIDindex = {}
        self.randMac = sofi_iftools.randomMAC(maxNum=10)
        #signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, signal, frame):
        logging.info("Exiting listener.")
        sys.exit(0)

    def init_sockets(self):
        """
        Initialize the sockets for communication with legacy clients and hostapd.
        """
        # Make sure the socket does not already exist
        try:
            os.unlink(IPC.PWIFI_LISTENER_INTERFACE)
        except OSError:
            if os.path.exists(IPC.PWIFI_LISTENER_INTERFACE):
                raise

        self.sock_listener = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock_hostapd = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock_legacy = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock_legacy.bind(('', IPC.PWIFI_IPC_PORT))
        self.sock_listener.bind(IPC.PWIFI_LISTENER_INTERFACE)
        self.rsockets = [self.sock_legacy, self.sock_listener]
        self.sockets = []

    def receive_msg(self, timeout=None):
        """
        Receive a message on the sockets.
        This method blocks indefinitely if no timeout (in seconds) is specified
        and no messages are received.
        Returns a (data, addr) tuple with the message and the sender address.
        """
        if len(self.sockets) == 0:
            self.sockets, _, _ = select.select(self.rsockets, [], [], timeout)

        if len(self.sockets) > 0:
            s = self.sockets.pop()
            data, addr = s.recvfrom(COMMON.MAXBUFLEN)
            return (data, addr)
    
    @print_timing
    def handle_disband(self, ssid, source_address):
        """
        Deal with an incoming disband message from hostapd.
        That means removing the active client state for the source of the disband.
        """
        ssidString = ssid.toString()
        reply = "" #Return an empty String!
        if(source_address in self.stateIndex):
            localState = self.stateIndex[source_address]
            if(localState.State == CONNECTED):
                if(localState.address == source_address): #This should be a given, but lets check it.
                    self.statelist.remove(localState)
                    del self.stateIndex[source_address]
                    del self.stateSSIDindex[ssidString]
                else:
                    logging.debug("Client Address does not match!")
            else:
                logging.debug("SOMETHING WENT WRONG! Client State was not connected, but disbanded!")
        elif(ssidString in self.stateSSIDindex):
            localState = self.stateSSIDindex[ssidString]
            self.statelist.remove(localState)
            del self.stateIndex[localState.address]
            del self.stateSSIDindex[ssidString]
            logging.info("Disbanded network with SSID: %s" %ssidString)
        else:
            logging.debug("Received Disband Notification, but no associated State was found!")
        return reply
    
    def _build_ACK(self,ssid,source_address,ip,localState,reply):
        if ip is not None:
            port = 8010
            url = "http://%s:%s/" %(ip,port)
            ie_app = (struct.pack('>BB', COMMON.PWIFI_EID_URL, len(url)) + url)
        ie_max_sta = struct.pack('>BBB', COMMON.PWIFI_EID_MAX_STA, 1, 1)
        psk = sofi_crypt.computePSK(ssid.toString(), localState.hashList[0])
        ie_psk = (struct.pack('>BB', COMMON.PWIFI_EID_PSK, len(psk)) + psk) #line 199, pwifi_hostapd.c needs to be changed!
        mac = self.randMac.getRandomMacBin()
        ie_mac = (struct.pack('>BB', COMMON.PWIFI_EID_MAC,len(mac))+mac)
        newSSID = ssid.toString()
        ie_ssid = (struct.pack('>BB', COMMON.PWIFI_EID_SSID, len(newSSID)) + newSSID)
        reply = reply + ie_psk + ie_max_sta + ie_mac + ie_ssid + ie_app
        ie_pwifi = struct.pack('>BB', COMMON.PWIFI_EID, len(reply))
        reply = IPC.PWIFI_IPC_ACK + ie_pwifi + reply
        return reply    
    
    @print_timing
    def handle_request(self, ssid, source_address, ip=None):
        """
        Handle an incoming request either from hostapd or a legacy client.
        That means that the required service is started and the response
        for hostapd / legacy client is prepared.
        Returns the message to be sent back.
        """
        reply = ""  # our reply for the request
        #reply = IPC.PWIFI_IPC_ACK
        if(source_address in self.stateIndex):
            #This is a request from a client that we are already communicating with!
            logging.debug("Address %s has existing State." %source_address)
            localState = self.stateIndex[source_address]
            if(localState.State == FAILED):
                logging.info("Deleting old State of address: %s" %source_address)
                self.statelist.remove(localState)
                del self.stateIndex[source_address]
                if(localState.lastSSID in self.stateSSIDindex):
                    del self.stateSSIDindex[localState.lastSSID]
                reply = IPC.PWIFI_IPC_NACK
                return reply
            else:
                if(localState.lastSSID == ssid.toString()):
                    logging.info("Duplicate Request received!")
                    if(localState.State == PUZZLE_SEND):
                        reply = localState.lastReply
                    else: 
                        reply = IPC.PWIFI_IPC_NACK # We can ignore this request as it was already answered!
                    return reply 
                else:
                    if(localState.State == REQUEST):
                        logging.error("State on second message was still REQUEST! This shouldnt happen!")
                    elif(localState.State == PUZZLE_SEND and localState.ComId == ssid.getID()):
                        #This must be the answer to the puzzle!
                        if(len(localState.DataItems)>0):
                            hashValue = localState.hashList[1]
                        else:
                            logging.debug("State found, but DataItems List is empty!")
                            reply = IPC.PWIFI_IPC_NACK
                            return reply # this should never happen!
                        ssidHash = ssid.getHash()
                        if(NO_PUZZLE):
                            puzzle_solution = 0
                        else:
                            puzzle_solution = sofi_crypt.xorDecode(ssidHash, hashValue)
                        if((NO_PUZZLE) or (self.puzzler.verifyPuzzleS(localState.Puzzle,puzzle_solution,bitSize=localState.bitSize))):
                            #The Client has successfully requested a file and solved the puzzle!
                            localState.stop_timeout()
                            localState.State = PUZZLE_SOLVED
                            localState.PuzzleSolution = puzzle_solution
                            localState.PuzzleSolved = True
                            del self.stateSSIDindex[localState.lastSSID] #delete the old SSID Index for this state
                            localState.lastSSID = ssid.toString()
                            self.stateSSIDindex[localState.lastSSID] = localState #Add the new SSID Index for this state!
                            
                            return self._build_ACK(ssid,source_address,ip,localState,reply)
                        else:
                            #Wrong solution to the puzzle!
                            #Drop that Client!
                            logging.info("Invalid Puzzle Solution received! Puzzle: %s Solution: %s" %(localState.Puzzle,puzzle_solution) )
                            localState.State = FAILED
                            self.statelist.remove(localState)
                            if(source_address in self.stateIndex):
                                del self.stateIndex[source_address]
                            if(ssid.toString() in self.stateSSIDindex):
                                del self.stateSSIDindex[ssid.toString()]
                            reply = IPC.PWIFI_IPC_NACK
                            return reply
                    else:
                        logging.info("Existing State found. State is: %s" %localState.State)
                        if(localState.State == PUZZLE_SOLVED):
                            logging.info("Last connect must have failed. Deleting old State of address: %s" %source_address)
                            self.statelist.remove(localState)
                            del self.stateIndex[source_address]
                            if(localState.lastSSID in self.stateSSIDindex):
                                del self.stateSSIDindex[localState.lastSSID]
                        reply = IPC.PWIFI_IPC_NACK
                        return reply
                        
        else:
            #A new Client request. We have to set up a state.
            logging.info("New Request received: " + ssid.toString())
            if(ssid.isPrivate()):
                SA,itemlist = self.database.getAvailable(ssid.getHash(),Address=source_address)
            else:
                SA,itemlist = self.database.getAvailable(ssid.getHash())
                
            if(len(itemlist)>0):
                localState = State(address=source_address)
                self.statelist.append(localState)
                self.stateIndex[source_address] = localState
                self.stateSSIDindex[ssid.toString()] = localState
                if(NO_PUZZLE):
                    localState.Puzzle = 0
                else:
                    localState.Puzzle = self.puzzler.createPuzzle(4)
                localState.SA = SA
                localState.ComId = ssid.getID()
                localState.DataItems = itemlist
                localState.lastSSID = ssid.toString()
                localState.hashList = itemlist[0].getHashList()
                if(SA != None):
                    key = SA.getKey()
                    for i,item in enumerate(localState.hashList):
                        localState.hashList[i] = sofi_crypt.xorDecode(item,key)
                #######PRE ACK! SIGNAL THE HostAPD to announce the SSID Hash2 XOR Puzzle
                if(NO_PUZZLE):
                    ssid.hash = localState.hashList[1]
                else:
                    ssid.hash = sofi_crypt.xorDecode(localState.hashList[1],localState.Puzzle)
                ssid.reply = True
                if(NO_PUZZLE):
                    ssid.bitSize = 0
                else:
                    ssid.bitSize = localState.bitSize
                    
                newSSID = ssid.toString()
                ie_ssid = (struct.pack('>BB', COMMON.PWIFI_EID_SSID, len(newSSID)) + newSSID)
                reply = reply + ie_ssid
                ie_pwifi = struct.pack('>BB', COMMON.PWIFI_EID, len(reply))
                reply = IPC.PWIFI_IPC_PACK + ie_pwifi + reply
                localState.lastReply = reply
                logging.info("Found Items in Database. Sending Puzzle!")
                localState.State = PUZZLE_SEND # puzzle is build and will be send now!
                localState.start_timeout() # start the timeout as last action before returning
                return reply
            else:
                #Nothing was found in the database for that specific client!
                logging.info("Nothing found in the Database for this Request!")
                reply = IPC.PWIFI_IPC_NACK
                return reply
        return reply


    def listen(self):
        """
        Listen for incoming service requests and provide as necessary.
        """
        self.init_sockets()
        self.dnsmasq = pwifi_dnsmasq.DnsmasqCTRL()
        self.dnsmasq.start()
        self.webserver = sofi_web.sofi_web(self.database,self.stateIndex)
        
        while True:
            logging.info("Waiting for messages...")
            data, addr = self.receive_msg()
            s = addr
            if s is None:
                s = "hostapd"
            logging.info("Received message from %s: %s" % (s, data))

            split_data = data.split()
            ssid = split_data[-1]
            request = split_data[0]
            source_address = sofi_iftools.sanitizeMac(split_data[1]) #source_address MAC
            # Requests from legacy clients only contain the request keyword
            # and SSID. Requests from hostapd provide the IP address which
            # will be used for the BSS as well.
            ip = None
            if len(split_data) == 4:
                ip = split_data[2]

            if(sofi_ssid.isSofiSSID(ssid)):
                ssidObject = sofi_ssid.ssid(SSID=ssid)
                if request == IPC.PWIFI_IPC_REQUEST:
                    reply = self.handle_request(ssidObject,source_address, ip=ip)
                    if len(reply) != 0:
                        if addr is None:
                            logging.info("Sending reply to hostapd: %s" %reply)
                            logging.info("Hex encoded reply: %s" %(sofi_crypt.hex(reply))) 
                            self.sock_hostapd.sendto(reply, IPC.PWIFI_HOSTAPD_INTERFACE)
                        else:
                            logging.info("Sending reply to legacy client " + addr)
                            self.sock_legacy.sendto(reply, addr)
                    else:
                        logging.info("Empty reply. Not sending a reply.")
                elif request == IPC.PWIFI_IPC_DISBAND:
                    reply = self.handle_disband(ssidObject,source_address)
                    # hostapd does not expect a reply on disband messages -> reply is empty String
                else:
                    logging.error("Invalid message format. Ignored: %s" %data)
                    continue
            else:
                logging.error("Not a valid SSID! Ignored!")
                continue


def main():
    logging.basicConfig(filename='sofi_listener.log', level=logging.DEBUG, datefmt='%d.%m %H:%M:%S')
    logging.info('So-Fi started listening for requests!')
    database = sofi_db.APdb()
    puzzler = sofi_puzzle.mk_preimage_puzzle()
    statelist = []
    listener = Listener(database,statelist,puzzler)
    listener.listen()

if __name__ == "__main__":
    main()
