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
This module implements the fast module scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import os, pdb
from forensics.win32.scan2 import PoolScanner
import forensics.commands
import forensics.conf
config=forensics.conf.ConfObject()
import forensics.utils as utils
from forensics.object2 import NewObject

class PoolScanModuleFast2(PoolScanner):
    pool_size = 0x4c
    pool_tag = "MmLd"
    
    def __init__(self):
        PoolScanner.__init__(self)
        self.add_constraint(self.check_blocksize_geq)
        self.add_constraint(self.check_pooltype_nonpaged_or_free)
        #self.add_constraint(self.check_poolindex)

class modscan2(forensics.commands.command):
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

    def parse_string(self, unicode_obj):
        ## We need to do this because the unicode_obj buffer is in
        ## kernel_address_space
        string_length = unicode_obj.Length.v()
        string_offset = unicode_obj.Buffer.v()            
        return self.kernel_address_space.read(
            string_offset, string_length).decode("utf16","ignore")
    
    def execute(self):
        ## Here we scan the physical address space
        address_space = utils.load_as(dict(type='physical'))

        ## We need the kernel_address_space later
        self.kernel_address_space = utils.load_as()
        
        print "%-50s %-12s %-8s %s \n" % ('File', 'Base', 'Size', 'Name')
        
        for offset in PoolScanModuleFast2().scan(address_space):
            ldr_entry = NewObject('_LDR_MODULE', vm=address_space,
                                  offset = offset)

            print "%-50s 0x%010x 0x%06x %s" % \
                  (self.parse_string(ldr_entry.FullDllName),
                   ldr_entry.BaseAddress,
                   ldr_entry.SizeOfImage,
                   self.parse_string(ldr_entry.ModuleName))
