'''
Created on 25 Sep 2009

@author: Mike Auty
'''

#pylint: disable-msg=C0111

import forensics.commands
import forensics.win32 as win32
import forensics.object2 as object2
import forensics.utils as utils
import socket

class sockets(forensics.commands.command):
    """Print list of open sockets"""

    def __init__(self, args=None):
        forensics.commands.command.__init__(self, args)
        self.profile = None

    def render_text(self, outfd, data):
        if len(data):
            outfd.write("%-6s %-6s %-6s %-26s\n" % ('Pid', 'Port', 'Proto', 'Create Time'))
        
        for sock in data:
            outfd.write("%-6s %-6s %-6s %-26s\n" % (int(sock.Pid), socket.ntohs(sock.LocalPort), int(sock.Protocol), sock.CreateTime))
        

    def calculate(self):
        self.profile = object2.Profile()

        addr_space = utils.load_as()
        
        # Get the Image Datetime
        result = win32.network.determine_sockets(addr_space, self.profile)

        return result