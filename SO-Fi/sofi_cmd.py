#!/usr/bin/env python

"""
The command line interface of the pwifi connection tool.


    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.
"""

import cmd
import signal
import sys
import sofi_native_client
import sofi_db
import logging

class Main(cmd.Cmd):
    """"Connection tool commandline interface."""

    prompt = "SO-Fi: "
    #client = sofi_native_client.Client()
    #database = sofi_db.STAdb()
    
    def emptyline(self):
        """Print an empty line on empty command input."""
        pass

    def _exit_signal_handler(self, signal, frame):
        """Exit program after receiving SIGTERM."""

        print "Exiting program."
        sys.exit(0)

    def _connect_signal_handler(self, signal, frame):
        """
        Handle 'connection established' notifications.
        """
        print "Connection established."

    def _disconnect_signal_handler(self, signal, frame):
        """
        Handle 'connection disestablished' notifications.
        """
        print "Connection lost."

    def _selection_dialog(self, list):
        """
        Prints a selection dialog of parsed items from config files.
        parsed_config is the config parsed with cfgparser.
        identifier    is the string used to categorize the elements from
                      which a selection is done. Eg. 'GROUPS'

        A 'name' element is expected for the elements of the given category.
        Selections will be listed by name.

        The actual selection is returned for a valid selection.
        None is returned on abortion or error.
        """
        print "Select Host:"
        item_list = []
        for i, item in enumerate(list):
            print "%d) %s" % (i, item.getName())
            item_list.append(item)

        print "\nSelect from 0-%d. Abort with %d." %(len(item_list) - 1,len(item_list))
        while True:
            try:
                s = raw_input("-> ")
            except EOFError:
                s = len(item_list)
                pass
            try:
                selected_value = int(s)
            except:
                continue

            if selected_value in range(0, len(item_list)):
                break
            elif selected_value == len(item_list):
                print " ...cancelled."
                return None

        return item_list[selected_value]

    def do_exit(self, line):
        """Exit command line interface."""
        self._exit_signal_handler(None, None)

    def do_EOF(self, line):
        """Exit command line interface."""
        self._exit_signal_handler(None, None)

    def do_get(self, target):
        """Get the given target."""

        if not target:
            print "Specify the target."
            return
        else:
            self.client.handle_get(target)

    def do_pget(self, target):
        """Privately get the given target."""
        if not target:
            print "Specify the target."
            return
        else:
            host = self._selection_dialog(self.database.getHostList())
            SA = self.database.getSAbyID(host.getSAId())
            if(SA != None):
                key = SA.getKey()
                self.client.handle_private_get(target, key)
            else:
                print "Could not find the Security Association for host: %s" %host.getName()
        
    def do_connect(self, identity):
        """
        Establish a simple connection with a pwifi network.
        Pass the identification of the user as argument.
        """

        if not identity:
            self.client.handle_connect("None")
        else:
            self.client.handle_connect(identity)

    def do_disconnect(self, line):
        """If a connection is established, disconnect it."""
        self.client.handle_disconnect()

    def do_reconnect(self, line):
        """
        Tell wpa_supplicant to reconnect. This only has an effect when
        a wpa_supplicant network is set up.
        """
        self.client.handle_reconnect()

    def do_status(self, line):
        """Print wpa_supplicant status."""
        print self.client.handle_get_status()

    def do_start(self, line):
        """Start wpa_supplicant."""
        self.client.handle_start()

    def do_stop(self, line):
        """Stop wpa_supplicant."""
        self.client.handle_stop()
        
    def do_scan(self, line):
        """Request a new scan"""
        self.client.handle_scan()
        
    def do_showif(self, line):
        """Get the configured Interfaces"""
        print self.client.handle_get_interfaces()
        
    def do_showmac(self,line):
        """Get the Mac Address"""
        print self.client.handle_get_mac()
        
    def do_setmac(self,line):
        """Set the Mac Addres"""
        print self.client.handle_set_mac(line)
        
    def do_ie(self, line):
        """
        Request the Information Element to a specific BSSID.
        """
        print self.client.handle_ie(line)
        
    def do_getscan(self, line):
        """Get the scan results from the wpa supplicant"""
        print self.client.handle_get_scan()

    def do_list_networks(self, line):
        """Get the list of configured networks from the WPA supplicant."""
        print self.client.handle_list_networks() 

    def do_remove_net(self,line):
        """Remove the Network with the <ID>"""
        print self.client.handle_remove_net(line)
                
def main():
    logging.basicConfig(filename='sofi_cmd.log',level=logging.DEBUG, datefmt='%d.%m %H:%M:%S')
    logging.info('Started!')
    m = Main()
    
    m.client = sofi_native_client.Client()
    m.database = sofi_db.STAdb()
    signal.signal(signal.SIGINT, m._exit_signal_handler)
    signal.signal(signal.SIGUSR1, m._connect_signal_handler)
    signal.signal(signal.SIGUSR2, m._disconnect_signal_handler)
    m.cmdloop()


if __name__ == "__main__":
    main()
