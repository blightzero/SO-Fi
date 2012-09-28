'''
Created on Jun 21, 2012

So-Fi Database component. Stores Security Associations between Clients and Hosts.
Stores Data Items available on a Host.
Allows for easy and fast search of Data Items and Security Associations.
Provides Host Database as well as a Client Database.
Host Database:
    Stores references to available Data Items and associated Security Associations
    
Client Database:
    Stores Hosts and their associated Security Associations.


    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.
'''
import hashlib
import os
import glob
import cPickle
import random
import sofi_crypt
import string
import time
import csv
import logging

class securityAssociation():
    """
    Security Association between two hosts.
    The Address field always describes the Client Address.
    """
    def __init__(self, SAId = 0, address="00:00:00:00:00:00",key="00000000000000000000",chained=False,chainIndex=0, name="default Name"):
        self._address = address
        self._key = key
        self._chained = chained
        self._chainIndex = chainIndex
        self._saId = SAId
        self._name = name 
        if(self.isChained()):
            self._createKeyChain()
    
    def _createKeyChain(self):
        """
        Create a chain of Hashes which we can use as a KeyChain in order to encrypt the communication.
        """
        self._keychain = []
        self._keychain.append(hashlib.sha1(self._key).digest())
        for _i in range(self._chainIndex):
            self._keychain.append(hashlib.sha1(self._keychain[-1]))
    
    def getName(self):
        """
        return the Name of this SA.
        Names are used to better identify security associations.
        """
        return self._name
    
    def getSAId(self):
        return self._saId
    
    def getAddress(self):
        return self._address
    
    def setAddress(self,address):
        self._address = address
    
    def getKey(self):
        """
        Return the current Key for this security association.
        For chained SAs this means that the current chainIndex is returned.
        """
        if(self._chained):
            return self._keychain[self._chainIndex]
        else:
            return self._key
    
    def setKey(self, key):
        """
        Set the Main Key.
        For chained SAs the chain is recomputed up to the current ChainIndex.
        """
        self._key = key
        if(self._chained):
            self._createKeyChain()
    
    def setChainIndex(self,index):
        """
        The chain Index is set and the chain is regenerated to the new ChainIndex
        * Should be called after setting the Key.
        """
        self._chainIndex = index
        self._createKeyChain()
        
    def getChainKey(self, Index):
        """
        Return a specific Key at Index from the Keychain.
        """
        return self._keychain[Index]
        
    def getKeyOnce(self):
        """
        Get a Key, delete it and decrease the chainIndex by one. 
        """
        if(self._chained):
            retVal = self._keychain.pop(self._chainIndex)
            self._chainIndex -= 1
            return retVal
        else:
            return None
    
    def isChained(self):
        """
        returns whether the SA is chained.
        """
        return self._chained
    
    def getChainIndex(self):
        """
        return the current index of the chain.
        """
        return self._chainIndex
    
    
class dataItem():
    
    def __init__(self,location="", descString="",serviceId=0,private=False,ACL=[],name="",h_eval=None):
        self._descString=descString
        self._serviceId=0
        self._private = private
        self._ACL = ACL
        self._location = location
        self._name = name
        self.h_eval = h_eval
        self._createHash()
        
    
    def _createHash(self):
        """
        Create the Hashes for this Item based on the given Description String.
        """
        if(self.h_eval):
            if(self.h_eval==1):
                self._eval_singleHash(self._sanitize(self._descString))
            elif(self.h_eval==2):
                self._eval_doubleHash(self._sanitize(self._descString))
            elif(self.h_eval==3):
                self._trippleHash(self._sanitize(self._descString))
        else:
            self._trippleHash(self._sanitize(self._descString))
        
    def _sanitize(self, s):
        """
        Return a sanitized version of the given string.
        """
        return sofi_crypt.sanitize(s)
    
    def _trippleHash(self, hashString):
        """
        Create a hashchain of length 3 for the input hashString and return it as a list.
        """
        self._hashlist = sofi_crypt.trippleHash(hashString)
    
    def _eval_singleHash(self, hashString):
        self._hashlist = sofi_crypt.singleHash(hashString)
    
    def _eval_doubleHash(self, hashString):
        hash1 = sofi_crypt.singleHash(hashString)
        hash2 = sofi_crypt.singleHash(hash1)
        self._hashlist = [hash1,hash2]
    
    def getHash(self, index):
        """
        Return the hash with the given index.
        """
        return self._hashlist[index]
    
    def getSearchHash(self):
        """
        Return the hash that is used as the initial search value.
        """
        if(self.h_eval != None):
            return self._hashlist[0]
        return self._hashlist[2]
    
    def getHashList(self):
        """
        Return the whole list of hashes.
        """
        return self._hashlist[:]
    
    def getACL(self):
        """
        return the Access Control List for this DataItem.
        Access Control List is a List of Security Association IDs that may access this object.
        """
        return self._ACL
    
    def isOnACL(self,search):
        """
        Check whether a certain ACL ID is on the ACL List for this item.
        If this is not a private Item ALWAYS return true.
        """
        if(self._private):
            #print "DEBUG: Checking ACL: %s" %search
            return (search in self._ACL)
        else:
            return True
    
    def getServiceId(self):
        """
        Return the Service ID for which this Item is intended.
        """
        return self._serviceId
    
    def addtoACL(self,SAId):
        """
        Add a SAId to the List of SAs that may access this object.
        """
        self._ACL.append(SAId)
        
    def removefromACL(self,sa):
        """
        Add a SA to the List of SAs that may access this object.
        """
        self._ACL.remove(sa)
    
    def isPublic(self):
        """
        Check whether this Item is a Public Item.
        """
        return not self._private
    
    def isPrivate(self):
        """
        Check whether this Item is a Public Item.
        """
        return self._private
    
    def getLocation(self):
        """
        Return the File Location for this Object.
        """
        return self._location
    
    def getDescription(self):
        """
        Get the description String of this Data Item
        """
        return self._descString
    
    def getName(self):
        """
        Get the Name Description of this DataItem.
        """
        return self._name
    
    def doSelfCheck(self):
        """
        Check whether the file that this DataItems describes still exists and is accessible.
        """
        if(not os.path.isfile(self._location)):
            return False
        else:
            return True
        
class host():
    """
    Host Class, associates a remote Address and a name with a Security Association for the STA Database.
    """
    def __init__(self,address="00:00:00:00:00:00",name="default_hostname",SAId=0):
        self._address = address
        self._name = name
        self._SAId = SAId
      
    def getAddress(self):
        """
        Get the Remote Address of the Host.
        """  
        return self._address
    
    def getName(self):
        """
        Get the Name associated with this Host/SA.
        """  
        return self._name
    
    def getSAId(self):
        """
        Return the ID of the security association that is associated with this host.
        """
        return self._SAId
    
    
class APdb():
    SAdict = {} #Dict Organized by their address
    SAIddict = {} # Dict Organized by their ID
    DIdict = {} #Dict Organized by the third Hash
    SAlist = [] #List of all SA
    DIlist = [] #List of all DI
    
    def __init__(self,Itemsfile=None,SAfile=None):
        if(SAfile != None):
            self._SAfile = SAfile
        else:
            self._SAfile = "sofi_AP_SecurityAssociations.db"
        if(Itemsfile != None):
            self._Itemsfile = Itemsfile
        else:
            self._Itemsfile = "sofi_DataItems.db"
            
        self._loadSAs(self._SAfile)
        self._loadDataItems(self._Itemsfile)
        logging.info('Database initialized. Using SA File: %s and Itemsfile: %s' %(self._SAfile,self._Itemsfile))

    def _checkOrphanedSA(self):
        """
        Check whether there are DataItems that still list SAs that do no longer exist.
        This might cause problems if the same ID is later reassigned to another SA.
        """
        for di in self.DIlist:
            tempList = di.getACL()
            tempList[:] = filter(self._checkInSAIddict,tempList)
    
    def _checkInSAIddict(self,SAId):
        """
        Function used for filtering the SAs that are not in the SA dictionary.
        """
        return (SAId in self.SAIddict)
        
    def _loadDataItems(self,ItemsFile):
        """
        Load the Database of the DataItems from a file.
        """
        if(not os.path.isfile(ItemsFile)):
            return None
        try:
            configFile = open(ItemsFile,"r")
            self.DIlist = cPickle.load(configFile)
            for lineItem in self.DIlist:
                if(not(lineItem.getSearchHash() in self.DIdict)):
                    self.DIdict[lineItem.getSearchHash()] = []
                self.DIdict[lineItem.getSearchHash()].append(lineItem)
            configFile.close()
            logging.info('Loaded Data Items from File.')
        except:
            logging.error('Failed to load Data Items!')
            return None
    
    def _saveDataItems(self,ItemsFile):
        """
        Save the Database of the DataItems to a file.
        """
        try:
            configFile = open(ItemsFile,"w")
            try:
                cPickle.dump(self.DIlist,configFile)
            except:
                return False
            configFile.close()
            logging.info('Saved Data Items to file.')
            return True
        except:
            logging.error('Saving Data Items failed!')
            return False
     
    def _loadSAs(self,SAFile):
        """
        Load security associations from a file.
        """
        if(not os.path.isfile(SAFile)):
            return False
        try:
            configFile = open(SAFile,"r")
            self.SAlist = cPickle.load(configFile)
        except:
            logging.error('Loading Security Associations failed!')
            return False
        #print "DEBUG: %s" %self.SAlist
        for lineSA in self.SAlist:
            #print "DEBUG: Adding SA %s" %lineSA
            self.SAIddict[lineSA.getSAId()] = lineSA
            if(not (lineSA.getAddress() in self.SAdict)):
                "DEBUG: Loading from file: SA not in SAdict so far!"
                self.SAdict[lineSA.getAddress()] = []
            self.SAdict[lineSA.getAddress()].append(lineSA)
        configFile.close()
        logging.info('Loaded Security Associations.')

    
    def _saveSAs(self,SAFile):
        """
        Save security associations to a file.
        """
        try:
            configFile = open(SAFile,"w")
            try:
                cPickle.dump(self.SAlist,configFile)
            except:
                return False
            configFile.close()
            logging.info('Saved Security Associations to file.')
            return True
        except:
            logging.error('Saving Security Associations failed!')
            return False
    
    def _findFreeSAId(self):
        """
        Find a new free ID for the security association.
        """
        random.seed()
        SAId = random.randint(0,10**6)
        t=0
        while((SAId in self.SAIddict) and (t<100)): #Try to find a Free Id 100 times.
            t+=1
            SAId = random.randint(0,10**6)
        if(t>=100):
            return -1
        return SAId
    
    def load(self):
        """
        Load Data Items and Security Associations
        """
        self._loadSAs(self._SAfile)
        self._loadDataItems(self._Itemsfile)
    
    def save(self):
        """
        Save Data Items and Security Associations
        """
        self._saveSAs(self._SAfile)
        self._saveDataItems(self._Itemsfile)
    
    def getdataItems(self):
        """
        Return the List of all DataItems
        """
        return self.DIlist
    
    def getSAs(self):
        """
        Return the List of all security associations.
        """
        return self.SAlist
    
    def getSA(self,SAId):
        if(SAId in self.SAIddict):
            return self.SAIddict[SAId]
        else:
            return None
    
    def addSA(self,address="00:00:00:00:00:00",key="00000000000000000000",chained=False,chainIndex=0,name="commonName"):
        """
        Create a new Security Association
        """
        SAId = self._findFreeSAId()
        if(SAId == -1):
            return False
        newSA = securityAssociation(SAId=SAId,address=address,key=key,chained=chained,chainIndex=chainIndex,name=name)
        self.SAlist.append(newSA)
        if(not(address in self.SAdict)):
            #print "DEBUG: Address not in SAdict so far."
            self.SAdict[address] = []
        self.SAdict[address].append(newSA)
        self.SAIddict[SAId] = newSA
        logging.info('Added new Security Association with Id: %s' %SAId)
        return SAId
        
    
    def removeSAbyAddress(self,address):
        """
        Remove SAs based on their Address
        * Having multiple SAs using the same Address should be avoided!
        """
        if((address!=None) and (address in self.SAdict)):
            for sa in self.SAdict[address]:
                self.removeSAbyID(sa.getSAId())
            return True
        else:
            return False

        
    def removeSAbyID(self,SAId):
        """
        Remove SA based on its ID
        """
        if((SAId!=None) and (SAId in self.SAIddict)):
            saId = self.SAIddict[SAId]
            address = saId.getAddress()
            self.SAdict[address].remove(saId)
            del self.SAIddict[SAId]
            self.SAlist.remove(saId)
            if(len(self.SAdict[address])==0):
                del self.SAdict[address]
            self._checkOrphanedSA()
            return True
        else:
            return False
        
    def addDataItem(self,location="", descString="",serviceId=0,private=False,ACL=[],name="",h_eval=None):
        """
        Add a new DataItem
        """
        newdItem = dataItem(location=location,descString=descString,serviceId=serviceId,private=private,ACL=ACL,name=name,h_eval=h_eval)
        self.DIlist.append(newdItem)
        if(not(newdItem.getSearchHash() in self.DIdict)):
            self.DIdict[newdItem.getSearchHash()] = []
        self.DIdict[newdItem.getSearchHash()].append(newdItem)
        logging.info('Added new Data Item.')
        return newdItem
    
    def removeDataItem(self,mHash=None,location=None):
        """
        Remove the DataItem
        """
        
        if((mHash!=None) and (location!=None)):
            """
            delete only DataItems found under that mHash with that particular location
            """
            if(mHash in self.DIdict):
                dIlist = self.DIdict[mHash]
                for dI in dIlist:
                    if(dI.getLocation() == location):
                        self.DIlist.remove(dI)
                        self.DIdict[mHash][:] = filter(lambda a: a==dI,self.Didict[mHash])
                return True
            else:
                return False
        elif(mHash!=None):
            """
            delete all DataItems with that particular mHash.
            """
            if(mHash in self.DIdict):
                dIlist = self.DIdict[mHash]
                for dI in dIlist:
                    self.DIlist.remove(dI)
                del self.DIdict[mHash]
                return True
            else:
                return False
        elif(location != None):
            """
            Find and delete all data Items with that particular location.
            """
            #self.DIlist[:] = filter(self._locationFilter,self.DIlist)
            self.DIlist[:] = [item for item in self.DIlist if self._locationFilter(item,location)]
            return True
        else:
            return False
                    
    
    def _locationFilter(self, x,location):
        """
        Returns False if location of passed item x matches, True if not!
        """
        if(x.getLocation()==location):
            if(x.getSearchHash() in self.DIdict): # remove it from the List in the Dictionary
                self.DIdict[x.getSearchHash()].remove(x)
            return False
        else:
            return True
    
    def _hashDecode(self,mHash,key):
        """
        Decode the passed mHash with the passed Key and return the result.
        Decoding is done via simple XOR.
        """
        return sofi_crypt.xorDecode(mHash, key)
    
    def getAvailable(self,ssidHash,SAId=None,Address=None):
        """
        Check whether a DataItem is available to a particular Address and Key(associated with the address).
        """
        SA = None
        dItemReturnList = []
        if((Address==None) and (SAId == None)):
            """
            If we do not get passed an address or SAId we only look for public DataItems.
            """
            if(ssidHash in self.DIdict):
                for dItem in self.DIdict[ssidHash]:
                    if(dItem.isPublic()):
                        dItemReturnList.append(dItem)
            logging.info('Found Public Data Item(s): %s' %dItemReturnList)
            return SA,dItemReturnList
        elif(Address != None):
            """
            Private Case: We first look up whether we have a SA for that specific Address
            then try to decode the ssidHash with the associated Key and look up whether we have that hash.
            After that we check whether the used SA has access to that particular DataItem.
            """
            if(Address in self.SAdict):
                #print "DEBUG: Found Address!"
                #print self.SAdict[Address]
                for address in self.SAdict[Address]: # It would be preferable if there was no collision of Addresses, as this could lead to a mixed List of different SAs if there was a collision of differently decoded Hashes           
                    searchHash = self._hashDecode(ssidHash,address.getKey())
                    #print "DEBUG: Decoded Hash: %s with key %s" %(searchHash,address.getKey())
                    if(searchHash in self.DIdict):
                        #print "DEBUG: Found Decoded Search Hash!"
                        logging.debug('Found Decoded Search Hash.')
                        for dItem in self.DIdict[searchHash]:
                            SA = address
                            #print "Searching Item that has matiching Security Association." 
                            if(dItem.isOnACL(address.getSAId())): # Collision should be very unlikely as we check for the SA here again... but still could happen...
                                dItemReturnList.append(dItem)
                        logging.debug('Found Items for Address: %s Items: %s' %(Address,dItemReturnList))       
                        return SA,dItemReturnList # this is why we already return on the first discovery of Matching Address/Key/Hash/SA
                return SA,dItemReturnList
        elif(SAId != None):
            """
            Check whether a ssidHash is available for a specific SA.
            """
            #print "Debug: SAID given."
            if(ssidHash in self.DIdict):
                #print "Debug: HASH found!"
                if(SAId in self.SAIddict):
                    #print "Debug: SAID found!"
                    SA = self.SAIddict[SAId]
                    for dItem in self.DIdict[ssidHash]:
                        #print "Debug: Checking %s" %dItem
                        if(dItem.isOnACL(SAId)):
                            
                            dItemReturnList.append(dItem)
            logging.debug('Found Items for specified Security Association: %s Items: %s' %(SAId,dItemReturnList))
            return SA,dItemReturnList
            
        return SA,dItemReturnList

class STAdb():
    hostList = [] # List of known Hosts
    SAlist = [] #List of all SA
    SAIddict = {}
    
    def __init__(self,Hostsfile=None,SAfile=None):
        if(SAfile != None):
            self._SAfile = SAfile
        else:
            self._SAfile = "sofi_STA_SecurityAssociations.db"
        if(Hostsfile != None):
            self._Hostsfile = Hostsfile
        else:
            self._Hostsfile = "sofi_STA_Hostfile.db"
        
        logging.info('Client Database initialized with SA File: %s and Hostsfile: %s' %(self._SAfile,self._Hostsfile))  
        self._loadSAs(self._SAfile)
        self._loadHosts(self._Hostsfile)
           
    def _loadSAs(self,SAFile):
        """
        Load security associations from a file.
        """
        if(not os.path.isfile(SAFile)):
            return False
        try:
            configFile = open(SAFile,"r")
            self.SAlist = cPickle.load(configFile)
        except:
            logging.error('Failed to load Security Associations from file: %s' %SAFile)
            return False
        #print "DEBUG: %s" %self.SAlist
        for lineSA in self.SAlist:
            #print "DEBUG: Adding SA %s" %lineSA
            self.SAIddict[lineSA.getSAId()] = lineSA
        logging.info('Loaded Security Associations.')
        configFile.close()

    
    def _saveSAs(self,SAFile):
        """
        Save security associations to a file.
        """
        try:
            configFile = open(SAFile,"w")
            try:
                cPickle.dump(self.SAlist,configFile)
            except:
                return False
            configFile.close()
            logging.info('Saved Security Associations to file.')
            return True
        except:
            logging.error('Failed to save Security Associations to file: %s' %SAFile)
            return False
    
    def _loadHosts(self,HostsFile):
        """
        Load Hosts from file.
        """
        if(not os.path.isfile(HostsFile)):
            return False
        try:
            configFile = open(HostsFile,"r")
        except:
            logging.error('Failed to load Hosts File: %s' %HostsFile)
            return False
        try:
            self.hostList = cPickle.load(configFile)
            configFile.close()
            logging.info('Loaded Hosts from File.')
            return True
        except:
            logging.error('Failed to load Hosts File: %s' %HostsFile)
            return False
        
    def _saveHosts(self,HostsFile):
        """
        Save Hosts to File.
        """
        try:
            configFile = open(HostsFile,"w")
            try:
                cPickle.dump(self.hostList,configFile)
            except:
                return False
            configFile.close()
            logging.info('Saved Hosts to File.')
            return True
        except:
            logging.error('Failed to save Hosts to File: %s' %HostsFile)
            return False        
    
    def _findFreeSAId(self):
        """
        Find a free ID for a security association.
        """
        random.seed()
        SAId = random.randint(0,10**6)
        t=0
        while((SAId in self.SAIddict) and (t<100)): #Try to find a Free Id 100 times.
            t+=1
            SAId = random.randint(0,10**6)
        if(t>=100):
            return -1
        return SAId
    
    def _checkOrphanedSA(self):
        """
        Check whether there are Hosts without an attached SA.
        """
        self.Hostlist[:] = filter(self._checkInSAIddict,self.Hostlist)
    
    def _checkInSAIddict(self,host):
        """
        Function used for filtering the SAs that are not in the SA dictionary.
        """
        return (host.getSAId() in self.SAIddict)
    
    def load(self):
        """
        Load Hosts and Security Associations
        """
        self._loadSAs(self._SAfile)
        self._loadHosts(self._Hostsfile)
    
    def save(self):
        """
        Save Hosts and Security Associations
        """
        self._saveSAs(self._SAfile)
        self._saveHosts(self._Hostsfile)

    def _addSA(self,address="00:00:00:00:00:00",key="00000000000000000000",chained=False,chainIndex=0,name="commonName"):
        """
        Create a new Security Association
        """
        SAId = self._findFreeSAId()
        if(SAId == -1):
            return False
        newSA = securityAssociation(SAId=SAId,address=address,key=key,chained=chained,chainIndex=chainIndex,name=name)
        self.SAlist.append(newSA)
        self.SAIddict[SAId] = newSA
        return SAId
        
    def _removeSAbyID(self,SAId):
        """
        Remove SA based on its ID
        """
        if((SAId!=None) and (SAId in self.SAIddict)):
            self.SAlist.remove(self.SAIddict[SAId])
            del self.SAIddict[SAId]
            self._checkOrphanedSA()
    
    def addHost(self,myaddress="00:00:00:00:00:00",remoteaddress="00:00:00:00:00:00",key="00000000000000000000",chained=False,chainIndex=0,name="commonName"):
        """
        Add a new Host with an according SA
        """
        SAId = self._addSA(address=myaddress,key=key,chained=chained,chainIndex=chainIndex,name=name)
        newHost = host(address=remoteaddress,name=name,SAId=SAId)
        self.hostList.append(newHost)
        return newHost
        
    def getHost(self,remoteaddress=None, name=None, SAId = None):
        """
        Get a Host, based on remoteaddress, name or SAID.
        """
        if(remoteaddress != None):
            for host in self.hostList:
                if(host.getAddress() == remoteaddress):
                    return host
        elif(name != None):
            for host in self.hostList:
                if(host.getName() == name):
                    return host
        elif(SAId != None):
            for host in self.hostList:
                if(host.getSAId() == SAId):
                    return host
        else:
            return None
        
    def getSAbyID(self,SAId):
        """
        Return the security association with a specific ID.
        """
        if(SAId in self.SAIddict):
            return self.SAIddict[SAId]
        else:
            return None
        
    def getHostList(self):
        """
        Return the Hostlist
        """
        return self.hostList
    
    def getSAList(self):
        """
        Return the SAlist
        """
        return self.SAlist

def speed_test(num_items):
    print "Loading Database..."
    start_time = time.clock()
    testAPDB = APdb()
    finish_time = time.clock() - start_time 
    a = finish_time
    print "Database with %s items loaded in %.09f sec" %(len(testAPDB.getdataItems()),finish_time)
    
    said1 = testAPDB.addSA(address="00:00:00:00:00:FF", key=sofi_crypt.singleHash("THISISMYKEYKEYKEY"), chained=False, chainIndex=0, name="horst")
    said2 = testAPDB.addSA(address="00:00:00:00:DE:AD", key=sofi_crypt.singleHash("THISISMYKEYKEYKEY"), chained=False, chainIndex=0, name="dings")
    item1 = testAPDB.addDataItem(location="/bin/bash", descString="bin bash", serviceId=2, private=True, ACL=[said1,said2])
    item2 = testAPDB.addDataItem(location="/bin/false", descString="bin false", serviceId=2, private=False, ACL=[])
    
    print "Adding %s items..." %num_items
    start_time = time.clock()
    for i in range(num_items):
        testAPDB.addDataItem(location=''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(50)), descString=''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(30)), serviceId=2, private=True, ACL=[said1,said2])
    finish_time = time.clock() - start_time
    b = finish_time
    print "Finished adding %s items in %0.6f sec" %(num_items,finish_time)
    
    SAid1 = testAPDB.getSA(said1)
    print "Staring search..."
    start_time = time.clock()
    SA,iteml = testAPDB.getAvailable(sofi_crypt.xorDecode(item1.getSearchHash(),SAid1.getKey()),Address=SAid1.getAddress())
    finish_time = time.clock() - start_time
    c = finish_time 
    #SA,iteml = testAPDB.getAvailable(item1.getSearchHash(),said1)
    if(len(iteml)>0):
        print "Found %s items." %len(iteml)
    print "Search finished in %.012f sec" %finish_time
    
    print "Saving Database..."
    start_time = time.clock()
    testAPDB.save()
    finish_time = time.clock() - start_time
    d = finish_time
    print "Finished saving Database with %s entries in %.09f sec." %(len(testAPDB.getdataItems()),finish_time)
    print "Currently holding %s security associations." %len(testAPDB.getSAs())
    return (len(testAPDB.getdataItems()),finish_time),a,b,c,d

def do_speed_test():
    num_items = 10000
    i,a,b,c,d = speed_test(num_items)
    writer = csv.writer(open("sofi_db_timing.csv","ab"))
    writer.writerow(i,a,b,c,d)

def station_test():
    stationDB = STAdb()
    print "Hostslist: %s" %stationDB.getHostList()
    host1 = stationDB.addHost(myaddress="00:00:DE:AD:BE:EF", remoteaddress="00:00:00:00:AF:FE", key = sofi_crypt.singleHash("THISISMYKEYKEYKEY"), chained=False, chainIndex=0, name="horst")
    print "Host added: %s" %host1
    host = stationDB.getHost(remoteaddress="00:00:00:00:AF:FE")
    print "Host searched by remoteaddress: %s" %host
    host = stationDB.getHost(name="horst")
    print "Host searched by name: %s" %host
    SAId = host1.getSAId()
    host = stationDB.getHost(SAId=SAId)
    print "Host searched by ID: %s" %host
    print "Hostslist: %s" %stationDB.getHostList()
    print "SA searched by ID: %s" %stationDB.getSAbyID(SAId)
    print "SA List: %s" %stationDB.getSAList()
    stationDB.save()
    print "Saved Database."

def add_dir(directory):
    APDB = APdb()
    if(os.path.isdir(directory)):
        for filename in glob.glob(directory + "/*"):
            fname = os.path.basename(filename).split(".")[0]
            directory_name = directory.split("/")[-1]
            print "Adding File: %s for Keyword: %s" %(fname,directory_name)
            APDB.addDataItem(location=os.path.abspath(filename), descString=directory_name, serviceId=2, private=False, ACL=[], name=fname)
            
            for desc in fname.split("_"):
                print "Adding File: %s for Keyword: %s" %(fname,desc)
                APDB.addDataItem(location=os.path.abspath(filename), descString=desc, serviceId=2, private=False, ACL=[], name=fname)
    APDB.save()
    
def add_pics(directory,name):
    APDB = APdb()
    if(os.path.isdir(directory)):
        for filename in glob.glob(directory + "/*"):
            if(name in filename):
                fname = os.path.basename(filename).split(".")[0]
                print "Adding File: %s for Keyword: %s" %(fname,name)
                APDB.addDataItem(location=os.path.abspath(filename), descString=name, serviceId=2, private=False, ACL=[], name=fname)
    APDB.save()
    
    
def eval_lookup():
    import platform
    import csv
    import time
     
    sample_no = 10000
    writer = csv.writer(open("lookup_" + platform.system() +"_"+ platform.node() +"_"+ platform.release()+ "_" + platform.processor() + ".csv","ab"))
    
    testAPDB = APdb(Itemsfile="EVALDB.db",SAfile="EVALSADB.db")
        
    said1 = testAPDB.addSA(address="00:00:00:00:00:FF", key=sofi_crypt.singleHash("THISISMYKEYKEYKEY"), chained=False, chainIndex=0, name="horst")
    said2 = testAPDB.addSA(address="00:00:00:00:DE:AD", key=sofi_crypt.singleHash("THISISMYKEYKEYKEY"), chained=False, chainIndex=0, name="dings")
    item1 = testAPDB.addDataItem(location="/bin/bash", descString="bin bash", serviceId=2, private=True, ACL=[said1,said2])
    item2 = testAPDB.addDataItem(location="/bin/false", descString="bin false", serviceId=2, private=False, ACL=[])
    SAid1 = testAPDB.getSA(said1)
    
    for i in xrange(6):
        result_list = ["%s" %(10**i)]
        for _j in xrange(10**i):
            testAPDB.addDataItem(location=''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(50)), descString=''.join(random.choice(string.ascii_uppercase + string.digits) for x in range(30)), serviceId=2, private=True, ACL=[said1,said2])
        for _k in xrange(sample_no):
            key = sofi_crypt.xorDecode(item1.getSearchHash(),SAid1.getKey())
            Address=SAid1.getAddress()
            start_time = time.time()
            SA,iteml = testAPDB.getAvailable(key,Address=Address)
            end_time = time.time()
            result_list.append(end_time - start_time)
        writer.writerow(result_list)
        
def eval_hashing():
    import platform
    from multiprocessing import Process
    import os
    import csv
    import time

    sample_no = 100
    writer = csv.writer(open("hashing_" + platform.system() +"_"+ platform.node() +"_"+ platform.release()+ "_" + platform.processor() + ".csv","ab"))
    
    for NO_HASHES in xrange(1,4):
        writer.writerow([NO_HASHES])
        for k in xrange(0,6):
            resultlist = [10**k]
            for _j in xrange(sample_no):
                start_time = time.time()
                p = Process(target=eval_hashing_func,args=(k,NO_HASHES))
                p.start()
                p.join() 
                end_time = time.time()
                resultlist.append(end_time - start_time)
            writer.writerow(resultlist)
    
def eval_hashing_func(k,NO_HASHES):
    
    testAPDB = APdb(Itemsfile="EVALDB.db",SAfile="EVALSADB.db")
    #f = open("eval_ids.txt","r")
    for _l in xrange(10**k):
        #key = f.readline()
        key = "%s" %sofi_crypt.randomKey(2)
        #if(key==""):
            #f.close()
            #f = open("eval_ids.txt","r")
            #key = f.readline()
        testAPDB.addDataItem(location="/bin/false", descString=key, serviceId=2, private=False, ACL=[],h_eval=NO_HASHES)
        #f.close()

if __name__ == "__main__":
    import sys
    if(len(sys.argv) > 3):
        if(sys.argv[1] == "round"):
            k = int(sys.argv[2])
            NO_HASHES = int(sys.argv[3])
            eval_hashing_func(k,NO_HASHES)
    else:
        #do_speed_test()
        #station_test()
        #add_dir("/var/tmp/sofi/mobicom")
        #add_pics("/var/tmp/sofi/pics","istanbul")
        #add_dir("/var/tmp/sofi/mobihoc")
        #add_pics("/var/tmp/sofi/pics","vegas")
        eval_hashing()
        
