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
This module implements the slow thorough process scanning

@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

from forensics.win32.scan2 import ThoroughScan
import forensics.commands
import forensics.conf
config = forensics.conf.ConfObject()
import forensics.utils as utils
from forensics.object2 import NewObject
import forensics.debug as debug

class PSScan(ThoroughScan):
    def __init__(self):
        ThoroughScan.__init__(self)
        self.add_constraint(self.check_dispatch_header_fast)
        self.add_constraint(self.check_dispatch_header)
        self.add_constraint(self.check_dtb_aligned)
        self.add_constraint(self.check_thread_list)
        self.add_constraint(self.check_synchronization)

    def check_dispatch_header_fast(self, offset):
        """ A Real fast first level checker for _EPROCESS process
        headers
        """
        ## We need to determine the offsets of the headers
        try:
            header = self.buffer.read(self.base_offset + offset + self.header_offset,
                                      4)
            if header[0] != "\x03" or header[2] != '\x1b':
                return False

        except AttributeError:
            eprocess = NewObject('_EPROCESS', vm=self.buffer,
                                 offset = self.base_offset)
            
            self.header_offset = eprocess.Pcb.Header.offset - eprocess.offset

        return True

    def check_dispatch_header(self, offset):
        self.eprocess = NewObject('_EPROCESS', vm=self.buffer,
                                  offset = self.base_offset + offset)
        
        header = self.eprocess.Pcb.Header
        return header.Type == 0x03 and \
                   header.Size == 0x1b
        
    def check_dtb_aligned(self, offset):
        dtb_offset = self.eprocess.Pcb.DirectoryTableBase[0].v()
        if dtb_offset % 0x20 == 0:
            return True

    def check_thread_list(self, offset):
        kernel = 0x80000000
        list_head = self.eprocess.ThreadListHead

        if list_head.Flink.v() > kernel and \
           list_head.Blink > kernel:
            return True

    def check_synchronization(self, offset):
        event = self.eprocess.WorkingSetLock.Event.Header
        if event.Type != 0x1 or event.Size != 0x4:
            return False

        event = self.eprocess.AddressCreationLock.Event.Header
        if event.Size == 0x4 and event.Type == 0x1:
            return True
        
class psscan(forensics.commands.command):
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

        cnt = 0
        print  "No.  PID    PPID   Time created             Time exited              Offset     PDB        Remarks\n"+ \
              "---- ------ ------ ------------------------ ------------------------ ---------- ---------- ----------------\n"
        
        for offset in PSScan().scan(address_space):
            eprocess = NewObject('_EPROCESS', vm=address_space, offset=offset)
            cnt += 1
            print "%4d %6d %6d %24s %24s 0x%0.8x 0x%0.8x %-16s" % (
                cnt,
                eprocess.UniqueProcessId,
                eprocess.InheritedFromUniqueProcessId,
                eprocess.CreateTime or '',
                eprocess.ExitTime or '',
                eprocess.offset,
                eprocess.Pcb.DirectoryTableBase[0],
                eprocess.ImageFileName)
