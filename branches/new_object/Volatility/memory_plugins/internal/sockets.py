'''
Created on 25 Sep 2009

@author: Mike Auty
'''

#pylint: disable-msg=C0111

import volatility.commands
import volatility.win32 as win32
import volatility.utils as utils

class sockets(volatility.commands.command):
    """Print list of open sockets"""
    def render_text(self, outfd, data):
        if len(data):
            outfd.write("%-6s %-6s %-6s %-26s\n" % ('Pid', 'Port', 'Proto', 'Create Time'))
        
        for sock in data:
            outfd.write("%-6d %-6d %-6d %-26s\n" % (sock.Pid, sock.LocalPort, sock.Protocol, sock.CreateTime))
        

    def calculate(self):
        addr_space = utils.load_as()
        
        result = win32.network.determine_sockets(addr_space)

        return result
