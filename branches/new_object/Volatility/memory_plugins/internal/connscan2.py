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
This module implements the fast connection scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import os
from forensics.win32.scan2 import PoolScanner
import forensics.commands
import forensics.conf
config=forensics.conf.ConfObject()
import forensics.utils as utils
from forensics.object2 import NewObject

class PoolScanConnFast2(PoolScanner):
    pool_size = 0x198
    pool_tag = "TCPT"
    
    def __init__(self):
        PoolScanner.__init__(self)
        self.add_constraint(self.check_blocksize_geq)
        self.add_constraint(self.check_pooltype_nonpaged_or_free)
        #self.add_constraint(self.check_poolindex)

class connscan2(forensics.commands.command):
    """ Scan Physical memory for _TCPT_OBJECT objects (tcp connections)
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
        address_space = utils.load_as(dict(type='physical'))

        print "Local Address             Remote Address            Pid   \n"+ \
              "------------------------- ------------------------- ------ \n"

        for offset in PoolScanConnFast2().scan(address_space):
            tcp_obj = NewObject('_TCPT_OBJECT', vm=address_space, offset=offset)
            local = "%s:%s" % (tcp_obj.LocalIpAddress, tcp_obj.LocalPort)
            remote = "%s:%s" % (tcp_obj.RemoteIpAddress, tcp_obj.RemotePort)
            print "%-25s %-25s %-6d" % (local, remote, tcp_obj.Pid)
