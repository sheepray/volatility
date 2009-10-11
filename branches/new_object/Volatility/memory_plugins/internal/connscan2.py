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

import volatility.win32.scan2 as scan2
import volatility.commands as commands
import volatility.conf as conf
config = conf.ConfObject()
import volatility.utils as utils
import volatility.object2 as object2
import volatility.debug as debug

class PoolScanConnFast2(scan2.PoolScanner):
    checks = [ ('PoolTagCheck', dict(tag = "TCPT")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x198)),
               ('CheckPoolType', dict(non_paged=True, free=True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class connscan2(commands.command):
    """ Scan Physical memory for _TCPT_OBJECT objects (tcp connections)
    """
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

        print "Local Address             Remote Address            Pid   \n"+ \
              "------------------------- ------------------------- ------ \n"

        ## We make a new scanner
        scanner = PoolScanConnFast2()
        for offset in scanner.scan(address_space):
            ## This yields the pool offsets - we want the actual object
            tcp_obj = object2.NewObject('_TCPT_OBJECT', vm=address_space,
                                offset=offset)
            
            local = "%s:%s" % (tcp_obj.LocalIpAddress, tcp_obj.LocalPort)
            remote = "%s:%s" % (tcp_obj.RemoteIpAddress, tcp_obj.RemotePort)
            print "%-25s %-25s %-6d" % (local, remote, tcp_obj.Pid)
