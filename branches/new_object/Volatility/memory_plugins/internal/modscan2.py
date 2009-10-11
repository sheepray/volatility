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

from forensics.win32.scan2 import PoolScanner, ScannerCheck
import forensics
config = forensics.conf.ConfObject()
import forensics.utils as utils
from forensics.object2 import NewObject
import forensics.debug as debug

class PoolScanModuleFast2(PoolScanner):
    preamble = ['_POOL_HEADER', ]

    checks = [ ('PoolTagCheck', dict(tag = 'MmLd')),
               ('CheckPoolSize', dict(condition = lambda x: x > 0x4c)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class modscan2(forensics.commands.command):
    """ Scan Physical memory for _LDR_DATA_TABLE_ENTRY objects
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
        address_space = utils.load_as(astype = 'physical')

        ## We need the kernel_address_space later
        self.kernel_address_space = utils.load_as()
        
        print "%-50s %-12s %-8s %s \n" % ('File', 'Base', 'Size', 'Name')

        scanner = PoolScanModuleFast2()
        for offset in scanner.scan(address_space):
            ldr_entry = NewObject('_LDR_DATA_TABLE_ENTRY', vm=address_space,
                                  offset = offset)

            print "%-50s 0x%010x 0x%06x %s" % \
                  (self.parse_string(ldr_entry.FullDllName),
                   ldr_entry.DllBase,
                   ldr_entry.SizeOfImage,
                   self.parse_string(ldr_entry.BaseDllName))

class CheckThreads(ScannerCheck):
    """ Check sanity of _ETHREAD """
    kernel = 0x80000000
    
    def check(self, found):
        start_of_object = self.address_space.profile.get_obj_size("_POOL_HEADER") +\
                          self.address_space.profile.get_obj_size("_OBJECT_HEADER") - 4
        
        thread = NewObject('_ETHREAD', vm=self.address_space,
                           offset=found + start_of_object)

        if thread.Cid.UniqueProcess.v()!=0 and \
           thread.ThreadsProcess.v() <= self.kernel:
            return False

        ## check the start address
        if thread.Cid.UniqueProcess.v() != 0 and \
           thread.StartAddress == 0:
            return False

        ## Check the Semaphores
        if thread.Tcb.SuspendSemaphore.Header.Size != 0x05 and \
               thread.Tcb.SuspendSemaphore.Header.Size != 0x05:
            return False
        
        if thread.LpcReplySemaphore.Header.Size != 5 and \
               thread.LpcReplySemaphore.Header.Type != 5:
            return False
        
        return True

class PoolScanThreadFast2(PoolScanner):
    """ Carve out threat objects using the pool tag """
    preamble = ['_POOL_HEADER', '_OBJECT_HEADER' ]

    checks = [ ('PoolTagCheck', dict(tag = '\x54\x68\x72\xe5')),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x278)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ('CheckThreads', {} ),
               ]

class thrdscan2(modscan2):
    def execute(self):
        ## Here we scan the physical address space
        address_space = utils.load_as(astype = 'physical')

        print "No.  PID    TID    Offset    \n"+ \
              "---- ------ ------ ----------\n"

        scanner = PoolScanThreadFast2()
        for found in scanner.scan(address_space):
            thread = NewObject('_ETHREAD', vm=address_space,
                               offset=found)
            
            print "%6d %6d 0x%0.8x" % (thread.Cid.UniqueProcess,
                                       thread.Cid.UniqueThread,
                                       thread.offset)
