'''
Created on Jul 31, 2012

    :copyright: (c) Copyright 2012 by Benjamin Grap.
    :license: BSD, see LICENSE for more details.

'''
import os
import logging

import cherrypy
from cherrypy.lib.static import serve_file
from cherrypy.process.plugins import Daemonizer

from sofi_config import *
from sofi_listener import State
import sofi_db
import sofi_ssid
import sofi_iftools
import sofi_crypt

def is_image(filename):
    """
    Check whether the given file is an image.
    Return True  if file is an image.
           False else.
    """
    if("jpg" in filename):
        return True

    return False


class Root:
    def __init__(self,fileIds,stateIndex,database):
        self.fileIds = fileIds
        logging.debug("FileIds Id: %s" %id(self.fileIds))
        self.stateIndex = stateIndex
        self.database = database
        
    def add_link(self, fileId, description):
        """
        Add a link to the given filename to the given html file.
        """
        fileId = sofi_crypt.hex(fileId)
        html = ('<a href="/download/?fileId=' + fileId + '">' + description + "</a> <br />")
        return html

    def embed_image(self, fileId, description):
        """
        Embed the given image file in the html file.
        """
        fileId = sofi_crypt.hex(fileId)
        html = ('<h3>%s:</h3><br /><img alt="%s" src="/download/?fileId=%s" />' %(description,description,fileId))
        return html

    def index(self, address="", request="", solution=""):
        logging.info("Request received. Address: %s Request: %s Solution: %s" %(address,request,solution))
        html = """<html><head><title>So-Fi</title></head><body>"""
        address = sofi_iftools.convertMacString(sofi_crypt.unhex(address))
        request = sofi_crypt.unhex(request)
        solution = sofi_crypt.unhex(solution)
        if(address!="" and (address in self.stateIndex)):
            localState = self.stateIndex[address]
            if((localState.PuzzleSolved) and ((localState.PuzzleSolution == solution) or NO_PUZZLE)):
                if(len(localState.DataItems)>0):
                    hashValue = localState.hashList[0]
                    logging.debug("Now using Hash: %s" %hashValue)
                    if(request == hashValue):
                        html += """<h2>Here are the selected file(s):</h2>"""
                        for item in localState.DataItems:
                            fileId = str(sofi_crypt.randomKey(10))
                            self.fileIds[fileId] = item
                            if(is_image(item.getLocation())):
                                html +=self.embed_image(fileId, item.getName())
                            else:
                                html +=self.add_link(fileId,item.getName())
                    else:
                        logging.info("Wrong request!")
                        html += """<h2>Wrong Request!</h2>"""
                else:
                    logging.error("No files were found for this request! This should never happen!")
                    html += """<h2>No files returned for your request!</h2>"""
            else:
                logging.info("Puzzle was not solved!")
                html += """<h2>Puzzle not solved!</h2>"""
        else:
            logging.info("Address was not found in state list.")
            html += """<h2>There is nothing for you here.</h2>"""
        
        
        html += """</body></html>"""
        return html
    
    index.exposed = True

class Download:
    def __init__(self,fileIds):
        self.fileIds = fileIds
        logging.debug("FileIds Id: %s" %id(self.fileIds))
    
    def index(self, fileId):
        logging.info("File Id requested: %s" %fileId)
        fileId = sofi_crypt.unhex(fileId)
        if(fileId in self.fileIds):
            dataItem = self.fileIds[fileId]
            logging.info("File Id found in File Id Dictonary!")
            if(dataItem.doSelfCheck()):
                logging.info("File ok! Serving file!")
                location = dataItem.getLocation()
                return serve_file(location, "application/x-download", "attachment")
        logging.info("File or File Id not found!")
        return "<html><head><title>NOT FOUND</title></head><body><h1>File not found!</h1></body></html>"
    index.exposed = True
    
class sofi_web:
    
    def __init__(self,database,stateIndex):
        self.database = database
        self.stateIndex = stateIndex
        self.fileIds = {}
        logging.debug("FileIds Id: %s" %id(self.fileIds))
        logging.info("Starting Webserver!")
        root = Root(self.fileIds,self.stateIndex,self.database)
        root.download = Download(self.fileIds)
        config = {"server.socket_host": "0.0.0.0", "server.socket_port": 8010}
        cherrypy.config.update(config)
        d = Daemonizer(cherrypy.engine)
        d.subscribe()
        cherrypy.tree.mount(root)
        cherrypy.engine.start()
        
        
        
