"""
Control dnsmasq.
"""

import os
import subprocess

# dnsmasq executable location
binary = os.path.dirname(os.path.abspath(__file__)) + "/dnsmasq"
#binary = "/usr/sbin/dnsmasq"
#SO-Fi config file location
cfg = os.path.dirname(os.path.abspath(__file__)) + "/sofi_dnsmasq.conf"


class DnsmasqCTRL():

    def start(self):
        """
        Start dnsmasq. If a dnsmasq daemon is already running it will be exited
        via its /etc/init.d script.
        """

        if os.access(binary, os.X_OK):
            print "Stopping existing dnsmasq instance."
            #subprocess.call(["/etc/init.d/dnsmasq", "stop"])
            print "Starting dnsmasq with pwifi config file."
            self.instance = subprocess.call([binary, "-C", cfg])
        else:
            print ("No dnsmasq binary found. Not providing DHCP for legacy clients. "
                   "Set path in '%s'." % os.path.abspath(__file__))

    def stop(self):
        """
        Stop the running dnsmasq instance.
        """

        if self.instance:
            print "Stopping dnsmasq."
            self.instance.terminate()
