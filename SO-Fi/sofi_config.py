'''
Created on Aug 13, 2012

@author: grap

    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.
'''

#GLOBALS
#Client Configuration
DELAY = .01
CLIENT_TIMEOUT = 30 #in Seconds
IDLE = 0
WAITING_FOR_RESPONSE = 1
RECEIVED_RESPONSE = 2
ANSWERED_PUZZLE = 3
CONNECTED = 4
WIFI_INTERFACE = "wlan0"


#GLOBALS
#Sofi_listener Configuration
REQUEST = 1
PUZZLE_SEND = 2
PUZZLE_SOLVED = 3
CONNECTED = 4
FAILED = 5
LISTENER_TIMEOUT = 10
NO_PUZZLE = False

#Common Config
SSID_PREFIX = "#;"
WPA_OFF = False
QUICK_MODE = False
IS_EVAL = True
