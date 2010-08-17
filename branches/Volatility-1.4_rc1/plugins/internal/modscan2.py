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

import volatility.scan as scan
import volatility.commands as commands
import volatility.conf as conf
config = conf.ConfObject()
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611

class PoolScanModuleFast2(scan.PoolScanner):
    preamble = ['_POOL_HEADER', ]

    checks = [ ('PoolTagCheck', dict(tag = 'MmLd')),
               ('CheckPoolSize', dict(condition = lambda x: x > 0x4c)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class modscan2(commands.command):
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

    def __init__(self, *args):
        commands.command.__init__(self, *args)
        self.kernel_address_space = None

    def parse_string(self, unicode_obj):
        ## We need to do this because the unicode_obj buffer is in
        ## kernel_address_space
        string_length = unicode_obj.Length.v()
        string_offset = unicode_obj.Buffer.v()
        return self.kernel_address_space.read(
            string_offset, string_length).decode("utf16", "ignore")

    def calculate(self):
        ## Here we scan the physical address space
        address_space = utils.load_as(astype = 'physical')

        ## We need the kernel_address_space later
        self.kernel_address_space = utils.load_as()

        scanner = PoolScanModuleFast2()
        for offset in scanner.scan(address_space):
            ldr_entry = obj.Object('_LDR_DATA_TABLE_ENTRY', vm = address_space,
                                  offset = offset)
            yield ldr_entry

    def render_text(self, outfd, data):
        outfd.write("{0:50} {1:12} {2:8} {3}\n".format('File', 'Base', 'Size', 'Name'))
        for ldr_entry in data:
            outfd.write("{0:50} 0x{1:010x} 0x{2:06x} {3}\n".format(
                         self.parse_string(ldr_entry.FullDllName),
                         ldr_entry.DllBase,
                         ldr_entry.SizeOfImage,
                         self.parse_string(ldr_entry.BaseDllName)))

class CheckThreads(scan.ScannerCheck):
    """ Check sanity of _ETHREAD """
    kernel = 0x80000000

    def check(self, found):
        start_of_object = self.address_space.profile.get_obj_size("_POOL_HEADER") + \
                          self.address_space.profile.get_obj_size("_OBJECT_HEADER") - 4

        thread = obj.Object('_ETHREAD', vm = self.address_space,
                           offset = found + start_of_object)

        if thread.Cid.UniqueProcess.v() != 0 and \
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

class PoolScanThreadFast2(scan.PoolScanner):
    """ Carve out threat objects using the pool tag """
    preamble = ['_POOL_HEADER', '_OBJECT_HEADER' ]

    checks = [ ('PoolTagCheck', dict(tag = '\x54\x68\x72\xe5')),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x278)),
               ('CheckPoolType', dict(non_paged = True, free = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ('CheckThreads', {}),
               ]

class thrdscan2(modscan2):
    """Scan physical memory for _ETHREAD objects"""
    def calculate(self):
        ## Here we scan the physical address space
        address_space = utils.load_as(astype = 'physical')

        scanner = PoolScanThreadFast2()
        for found in scanner.scan(address_space):
            thread = obj.Object('_ETHREAD', vm = address_space,
                               offset = found)

            yield thread

    def render_text(self, outfd, data):
        outfd.write("PID    TID    Create Time               Exit Time                 Offset    \n" + \
                    "------ ------ ------------------------- ------------------------- ----------\n")

        for thread in data:
            outfd.write("{0:6} {1:6} {2: <25} {3: <25} 0x{4:08x}\n".format(thread.Cid.UniqueProcess,
                                                                           thread.Cid.UniqueThread,
                                                                           thread.CreateTime or '',
                                                                           thread.ExitTime or '',
                                                                           thread.offset))



