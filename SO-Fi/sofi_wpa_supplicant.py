"""
Control wpa_supplicant.

    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.

"""

import os
import sys
import subprocess
import time
import logging

#Add Path(s) for the wpactrl library
sys.path.append('/home/blightzero/workspace/So-Fi/pywpactrl/build/lib.linux-x86_64-2.7')
sys.path.append('/home/grap/Dropbox/workspace-laptop/So-Fi/pywpactrl/build/lib.linux-x86_64-2.7')
sys.path.append('/home/mobac/So-Fi/pywpactrl/build/lib.linux-x86_64-2.7')
try:
    import wpactrl
except:
    print 'Could not find pywpactrl library. Aborting.'
    sys.exit(1)



#Control Interface Directory for the usual case
CTRL_IFACE_DIR = "/var/run/wpa_supplicant/"
#Place to put the Control Interface if we manually start it
CTRL_IFACE = "/var/run/wpa_supplicant/global"
#Paths to the wpa_supplicant binary
WPA_SUPP_PATHS = ["/system/bin/","/sbin/"]


class Wpa_supplicant_controller:
    """
    Control an instance of wpa_supplicant.
    Start, stop, establish connections with networks.
    """
    
    def __init__(self):
        self._ctrl_iface_dir = CTRL_IFACE_DIR
        self._connect_wpa_supplicant()

    def _connect_wpa_supplicant(self,ctrl_iface_dir=None):
        """
        Connect to a wpa_supplicant in order to control it.
        """
        if(ctrl_iface_dir!=None):
            self._ctrl_iface_dir = ctrl_iface_dir
            
        sockets = []
        if os.path.isdir(self._ctrl_iface_dir):
            try:
                sockets = [os.path.join(self._ctrl_iface_dir, i) for i in os.listdir(self._ctrl_iface_dir)]
            except OSError, error:
                logging.error('Error: %s'  %error)
                return False
            
            if len(sockets) < 1:
                logging.error('No wpa_ctrl sockets found in %s, aborting.' % self._ctrl_iface_dir )
                return False
                
        elif os.path.isfile(self._ctrl_iface_dir):
            sockets = [self._ctrl_iface_dir]
            
        else:
            logging.error('No wpa_ctrl sockets found. Aborting.')
            return False
        
        self.wpa_supplicant = None
        self.wpa_event = None
        for s in sockets:
            try:
                self.wpa_supplicant = wpactrl.WPACtrl(s)
                self.wpa_event = wpactrl.WPACtrl(s)
                if(self.wpa_supplicant.request("PING")=='PONG\n'):
                    break
            except wpactrl.error,error:
                logging.error('Could not connect to wpa_supplicant! Trying next socket.')
                return False
        
        
        if(self.wpa_supplicant == None):
            logging.error('Could not connect to wpa_supplicant! Aborting!')
            return False
        else:
            self.wpa_event.attach()
            if(self.wpa_event.attached==1):
                return True
            else:
                logging.error('Could not attach to wpa_supplicant! Aborting!')
                return False
    
    def wpa_supplicant_get_event(self):
        try:
            if(self.wpa_event.pending()):
                return self.wpa_event.recv()
            else:
                return None
        except:
            logging.error('Error: Could not get wpa_supplicant event!')
            return None
    
    def wpa_supplicant_event_pending(self):
        try:
            return self.wpa_event.pending()
        except:
            logging.error('Error: Could not get pending events.')
            return None
    
    def wpa_supplicant_is_running(self):
        """
        Determine whether wpa_supplicant is running by pinging it with wpa_cli.
        Returns true  if wpa_supplicant is running.
                false else
        """
        try:
            if(self.wpa_supplicant.request("PING")=='PONG\n'):
                return True
            else:
                return False
        except:
            return False

    def wpa_supplicant_get_scan(self):
        if self.wpa_supplicant_is_running():
            return self.wpa_supplicant.request("SCAN_RESULTS")

    def wpa_supplicant_get_bss(self,idx):
        if self.wpa_supplicant_is_running():
            return self.wpa_supplicant.request("BSS %s" %idx)

    def wpa_supplicant_get_status(self):
        """Get the status of wpa_supplicant."""
        if self.wpa_supplicant_is_running():
            return self.wpa_supplicant.request("STATUS")


    def stop_wpa_supplicant(self):
        """Terminate wpa_supplicant gracefully."""
        if self.wpa_supplicant_is_running():
            print "Stopping wpa_supplicant."
            self.wpa_supplicant.request("TERMINATE")
        else:
            print "wpa_supplicant is not running."


    def start_wpa_supplicant(self):
        """
        Start wpa_supplicant.
        """
        if self.wpa_supplicant_is_running():
            logging.error("wpa_supplicant already running.")
            return
        else:
            logging.info("Starting wpa_supplicant...")
            wpa_supplicant_binary = None
            for p in WPA_SUPP_PATHS:
                if os.access(p + "wpa_supplicant", os.X_OK):
                    wpa_supplicant_binary = p + "wpa_supplicant"
                    break
            if wpa_supplicant_binary is None:
                raise IOError("wpa_supplicant binary not existing or not executable.")
            subprocess.Popen(["sudo", wpa_supplicant_binary, "-g", CTRL_IFACE, "-B"])
            # wpa_supplicant messes up occasionally when it is supposed to
            # starting like this. Giving it a short moment seems to fix it.
            time.sleep(1)
            self._connect_wpa_supplicant(CTRL_IFACE)


    def wpa_supplicant_connect(self, ssid, pwd=None):
        """
        Try to connect to the given network with the given password.
        """
        if not self.wpa_supplicant_is_running():
            self.start_wpa_supplicant()

        logging.info( "Requesting Network: '%s'." % ssid)
        
        self.wpa_supplicant.request("AP_SCAN 1")
        n_id = self.wpa_supplicant.request("ADD_NETWORK").split()[-1]
        if(n_id != 'FAIL'):
            if(self.wpa_supplicant.request("SET_NETWORK " + n_id + " ssid " + '"%s"' %ssid) == 'OK\n'):
                if pwd is None:
                    self.wpa_supplicant.request("SET_NETWORK " + n_id + " key_mgmt NONE")
                else:
                    self.wpa_supplicant.request("SET_NETWORK " + n_id + " key_mgmt WPA-PSK")
                    self.wpa_supplicant.request("SET_NETWORK " + n_id + " pairwise CCMP TKIP")
                    self.wpa_supplicant.request("SET_NETWORK " + n_id + " group CCMP TKIP")
                    self.wpa_supplicant.request("SET_NETWORK " + n_id + ' psk %s' %pwd)
                self.wpa_supplicant.request("SET_NETWORK " + n_id + " scan_ssid " + "1")
                self.wpa_supplicant.request("ENABLE_NETWORK " + n_id)
                self.wpa_supplicant.request("SELECT_NETWORK " + n_id)
                self.wpa_supplicant.request("SCAN")
            else:
                logging.error("Setting SSID for Network failed.")
        else:
            logging.error("Setting up new Network failed.")

        return n_id
    
    def wpa_supplicant_remove_net(self, n_id):
        if self.wpa_supplicant_is_running():
            self.wpa_supplicant.request("REMOVE_NETWORK %s" % n_id)
            
    def wpa_supplicant_scan(self):
        if self.wpa_supplicant_is_running():
            self.wpa_supplicant.request("SCAN")
    
    def wpa_supplicant_interfaces(self):
        if self.wpa_supplicant_is_running():
            return self.wpa_supplicant.request("INTERFACES")
    
    def wpa_supplicant_disconnect(self):
        if not self.wpa_supplicant_is_running():
            logging.error("wpa_supplicant is not running.")
            return

        self.wpa_supplicant.request("DISCONNECT")

    def wpa_supplicant_list_networks(self):
        if not self.wpa_supplicant_is_running():
            logging.error("wpa_supplicant is not running.")
            return
        return self.wpa_supplicant.request("LIST_NETWORKS")

    def wpa_supplicant_reconnect(self):
        if not self.wpa_supplicant_is_running():
            logging.error("wpa_supplicant is not running.")
            return

        self.wpa_supplicant.request("RECONNECT")
