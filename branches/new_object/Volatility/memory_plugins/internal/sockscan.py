# Volatility
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
This module implements the fast socket scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

from forensics.win32.scan2 import PoolScanner, ScannerCheck
import forensics.commands
import forensics.conf
config = forensics.conf.ConfObject()
import forensics.utils as utils
from forensics.object2 import NewObject
import forensics.debug as debug

class CheckSocketCreateTime(ScannerCheck):
    """ Check that _ADDRESS_OBJECT.CreateTime makes sense """
    def __init__(self, address_space, condition = lambda x: x, **kwargs):
        self.condition  = condition
        self.address_space = address_space

    def check(self, offset):
        start_of_object = self.address_space.profile.get_obj_size("_POOL_HEADER") - 4
        address_obj = NewObject('_ADDRESS_OBJECT', vm=self.address_space,
                                offset=offset + start_of_object)

        return self.condition(address_obj.CreateTime.v())

class PoolScanSockFast(PoolScanner):
    checks = [ ('PoolTagCheck', dict(tag = "TCPA")),
               ('CheckPoolSize', dict(condition = lambda x: x == 0x170)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ## Valid sockets have time > 0
               ('CheckSocketCreateTime', dict(condition = lambda x: x > 0)),
               ('CheckPoolIndex', dict(value = 0))
               ]
    
class sockscan(forensics.commands.command):
    """ Scan Physical memory for _ADDRESS_OBJECT objects (tcp sockets)
    """

    # Declare meta information associated with this plugin
    
    meta_info = dict(
        author = 'Brendan Dolan-Gavitt',
        copyright = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt',
        contact = 'bdolangavitt@wesleyan.edu',
        license = 'GNU General Public License 2.0 or later',
        url = 'http://moyix.blogspot.com/',
        os = 'WIN_32_XP_SP2',
        version = '1.0',
        )
    
    def execute(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(astype = 'physical')
        
        print "PID    Port   Proto  Create Time                Offset \n"+ \
              "------ ------ ------ -------------------------- ----------\n"

        scanner = PoolScanSockFast()
        for offset in scanner.scan(address_space):
            sock_obj = NewObject('_ADDRESS_OBJECT', vm=address_space,
                                 offset=offset)
            
            print "%-6d %-6d %-6d %-26s 0x%0.8x" % (sock_obj.Pid, sock_obj.LocalPort,
                                                    sock_obj.Protocol, \
                                                    sock_obj.CreateTime, sock_obj.offset)
