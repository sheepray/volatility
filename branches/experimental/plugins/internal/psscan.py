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

import volatility.scan as scan
import volatility.conf as conf
import volatility.commands as commands
import volatility.utils as utils
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
config = conf.ConfObject()

class DispatchHeaderCheck(scan.ScannerCheck):
    """ A very fast check for an _EPROCESS.Pcb.Header.

    This check assumes that the type and size of
    _EPROCESS.Pcb.Header are unsigned chars, but allows their
    offsets to be determined from vtypes (so they could change
    between OS versions).
    """
    order = 10
    
    def __init__(self, address_space, **kwargs):
        ## Because this checks needs to be super fast we first
        ## instantiate the _EPROCESS and work out the offsets of the
        ## type and size members. Then in the check we just read those
        ## offsets directly.
        eprocess = obj.Object("_EPROCESS", vm=address_space, offset=0)
        self.type = eprocess.Pcb.Header.Type
        self.size = eprocess.Pcb.Header.Size
        self.buffer_size = max(self.size.offset, self.type.offset) + 2
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        data = self.address_space.read(offset + self.type.offset, self.buffer_size)
        return data[self.type.offset] == "\x03" and data[self.size.offset] == "\x1b"

    def skip(self, data, offset, base_offset):
        try:
            nextval = data.index("\x03", offset+1)
            return nextval - self.type.offset - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset

class DispatchThreadHeaderCheck(DispatchHeaderCheck):
    def __init__(self, address_space, **kwargs):
        ## Because this checks needs to be super fast we first
        ## instantiate the _EPROCESS and work out the offsets of the
        ## type and size members. Then in the check we just read those
        ## offsets directly.
        DispatchHeaderCheck.__init__(self, address_space, **kwargs)
        ethread = obj.Object("_ETHREAD", vm=address_space, offset=0)
        self.type = ethread.Tcb.Header.Type
        self.size = ethread.Tcb.Header.Size
        self.buffer_size = max(self.size.offset, self.type.offset) + 2

    def check(self, offset):
        data = self.address_space.read(offset + self.type.offset, self.buffer_size)
        return data[self.type.offset] == "\x06" and data[self.size.offset] == "\x70"

    def skip(self, data, offset, base_offset):
        try:
            nextval = data.index("\x06", offset+1)
            return nextval - self.type.offset - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset

class CheckDTBAligned(scan.ScannerCheck):
    """ Checks that _EPROCESS.Pcb.DirectoryTableBase is aligned to 0x20 """
    def check(self, offset):
        eprocess = obj.Object("_EPROCESS", vm=self.address_space,
                             offset = offset)

        return eprocess.Pcb.DirectoryTableBase % 0x20 == 0

class CheckThreadList(scan.ScannerCheck):
    """ Checks that _EPROCESS thread list points to the kernel Address Space """
    def check(self, offset):
        eprocess = obj.Object("_EPROCESS", vm=self.address_space,
                             offset = offset)
        kernel = 0x80000000
        
        list_head = eprocess.ThreadListHead

        if list_head.Flink > kernel and \
               list_head.Blink > kernel:
            return True

class CheckSynchronization(scan.ScannerCheck):
    """ Checks that _EPROCESS.WorkingSetLock and _EPROCESS.AddressCreationLock look valid """
    def check(self, offset):
        eprocess = obj.Object("_EPROCESS", vm=self.address_space,
                             offset = offset)
        
        event = eprocess.WorkingSetLock.Event.Header
        if event.Type != 0x1 or event.Size != 0x4:
            return False

        event = eprocess.AddressCreationLock.Event.Header
        if event.Size == 0x4 and event.Type == 0x1:
            return True

class CheckThreadSemaphores(scan.ScannerCheck):
    """ Checks _ETHREAD.Tcb.SuspendSemaphore and _ETHREAD.LpcReplySemaphore """
    def check(self, offset):
        ethread = obj.Object("_ETHREAD", vm=self.address_space,
                             offset = offset)

        pid = ethread.Cid.UniqueProcess
        if pid == 0:
            return True

        sem = ethread.Tcb.SuspendSemaphore.Header
        if sem.Type != 0x5 or sem.Size != 0x5:
            return False

        event = ethread.LpcReplySemaphore.Header
        if event.Size == 0x5 and event.Type == 0x5:
            return True

class CheckThreadNotificationTimer(scan.ScannerCheck):
    """ Checks for sane _ETHREAD.Tcb.Timer.Header """
    def check(self, offset):
        ethread = obj.Object("_ETHREAD", vm=self.address_space,
                            offset = offset)

        sem = ethread.Tcb.Timer.Header
        if sem.Type == 0x8 and sem.Size == 0xa:
            return True

class CheckThreadProcess(scan.ScannerCheck):
    """ Check that _ETHREAD.Cid.UniqueProcess is in kernel space """
    kernel = 0x80000000
    def check(self, offset):
        ethread = obj.Object("_ETHREAD", vm=self.address_space,
                            offset = offset)
        if ethread.Cid.UniqueProcess == 0 or ethread.ThreadsProcess > self.kernel:
            return True

class CheckThreadStartAddress(scan.ScannerCheck):
    """ Checks that _ETHREAD.StartAddress is not 0 """
    def check(self, offset):
        ethread = obj.Object("_ETHREAD", vm=self.address_space,
                            offset = offset)
        if ethread.Cid.UniqueProcess == 0 or ethread.StartAddress != 0:
            return True

class ThreadScan(scan.BaseScanner):
    """ Carves out _ETHREAD structures """
    checks = [ ("DispatchThreadHeaderCheck", {}),
               ("CheckThreadProcess", {}),
               ("CheckThreadStartAddress", {}),
               ("CheckThreadNotificationTimer", {}),
               ("CheckThreadSemaphores", {})
               ]

class thrdscan(commands.command):
    """ Scan Physical memory for _ETHREAD objects"""
    def calculate(self):
        address_space = utils.load_as(astype = 'physical')
        for offset in ThreadScan().scan(address_space):
            yield obj.Object('_ETHREAD', vm=address_space, offset=offset)

    def render_text(self, outfd, data):
        ## Just grab the AS and scan it using our scanner
        outfd.write("PID    TID    Create Time               Exit Time                 Offset    \n" + \
                    "------ ------ ------------------------- ------------------------- ----------\n")

        for ethread in data:
            outfd.write("{0:6} {1:6} {2: <25} {3: <25} 0x{4:08x}\n".format(ethread.Cid.UniqueProcess,
                                                                           ethread.Cid.UniqueThread,
                                                                           ethread.CreateTime or '',
                                                                           ethread.ExitTime or '',
                                                                           ethread.offset))
   
class PSScan(scan.DiscontigScanner):
    """ This scanner carves things that look like _EPROCESS structures.

    Since the _EPROCESS does not need to be linked to the process
    list, this scanner is useful to recover terminated or cloaked
    processes.
    """
    checks = [ ("DispatchHeaderCheck", {}),
               ("CheckDTBAligned", {}),
               ("CheckThreadList", {}),
               ("CheckSynchronization", {})
               ]

class psscan(commands.command):
    """ Scan Physical memory for _EPROCESS objects"""

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

    def calculate(self):
        address_space = utils.load_as(astype = 'physical')

        for offset in PSScan().scan(address_space):
            yield obj.Object('_EPROCESS', vm=address_space, offset=offset)

    def render_dot(self, outfd, data):
        objects = set()
        links = set()
        
        for eprocess in data:
            label = "{0} | {1} |".format(eprocess.UniqueProcessId,
                                         eprocess.ImageFileName)
            if eprocess.ExitTime:
                label += "exited\\n{0}".format(eprocess.ExitTime)
                options = ' style = "filled" fillcolor = "lightgray" '
            else:
                label += "running"
                options = ''

            objects.add('pid{0} [label="{1}" shape="record" {2}];\n'.format(eprocess.UniqueProcessId,
                                                                            label, options))
            links.add("pid{0} -> pid{1} [];\n".format(eprocess.InheritedFromUniqueProcessId,
                                                      eprocess.UniqueProcessId))

        ## Now write the dot file
        outfd.write("digraph processtree { \ngraph [rankdir = \"TB\"];\n")
        for link in links:
            outfd.write(link)

        for item in objects:
            outfd.write(item)
        outfd.write("}")
        
    def render_text(self, outfd, data):
        ## Just grab the AS and scan it using our scanner
        outfd.write("PID    PPID   Time created             Time exited              Offset     PDB        Remarks\n"+ \
                    "------ ------ ------------------------ ------------------------ ---------- ---------- ----------------\n")
        
        for eprocess in data:
            outfd.write("{0:6} {1:6} {2:24} {3:24} 0x{4:08x} 0x{5:08x} {6:16}\n".format(
                eprocess.UniqueProcessId,
                eprocess.InheritedFromUniqueProcessId,
                eprocess.CreateTime or '',
                eprocess.ExitTime or '',
                eprocess.offset,
                eprocess.Pcb.DirectoryTableBase,
                eprocess.ImageFileName))
