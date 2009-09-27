'''
Created on 25 Sep 2009

@author: Mike Auty
'''

#pylint: disable-msg=C0111

import forensics.commands
import forensics.win32 as win32
import forensics.object2 as object2
import forensics.utils as utils

class connections(forensics.commands.command):
    """
    Print list of open connections
    ------------------------------

    This module follows the handle table of each task and prints
    current connections.

    Note that if you are using a hibernated image this might not work
    because Windows closes all sockets before hibernating. You might
    find it more effective to do conscan instead.
    """

    def __init__(self, args=None):
        forensics.commands.command.__init__(self, args)
        self.profile = None

    def render_text(self, outfd, data):
        if len(data):
            outfd.write("%-25s %-25s %-6s\n" % ('Local Address', 'Remote Address', 'Pid'))
        
        for conn in data:
            local = "%s:%s" % (conn.LocalIpAddress, conn.LocalPort)
            remote = "%s:%s" % (conn.RemoteIpAddress, conn.RemotePort)
            outfd.write("%-25s %-25s %-6d\n" % (local, remote, conn.Pid))
        

    def calculate(self):
        result = {}
        self.profile = object2.Profile()

        addr_space = utils.load_as(self.opts)
        
        # Get the Image Datetime
        result = win32.network.determine_connections(addr_space, self.profile)

        return result
