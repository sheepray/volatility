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
import time
config = conf.ConfObject()
import volatility.utils as utils
import volatility.object2 as object2
import volatility.debug as debug

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
        eprocess = object2.NewObject("_EPROCESS", vm=address_space, offset=0)
        self.type = eprocess.Pcb.Header.Type
        self.size = eprocess.Pcb.Header.Size
        self.buffer_size = max(self.size.offset, self.type.offset) + 2
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        data = self.address_space.read(offset + self.type.offset, self.buffer_size)
        return data[self.type.offset] == "\x03" and data[self.size.offset] == "\x1b"

    def skip(self, data, offset):
        try:
            next = data.index("\x03", offset+1)
            return next - self.type.offset - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset

class DispatchThreadHeaderCheck(DispatchHeaderCheck):
    def __init__(self, address_space, **kwargs):
        ## Because this checks needs to be super fast we first
        ## instantiate the _EPROCESS and work out the offsets of the
        ## type and size members. Then in the check we just read those
        ## offsets directly.
        ethread = object2.NewObject("_ETHREAD", vm=address_space, offset=0)
        self.type = ethread.Tcb.Header.Type
        self.size = ethread.Tcb.Header.Size
        self.buffer_size = max(self.size.offset, self.type.offset) + 2
        scan.ScannerCheck.__init__(self, address_space)

    def check(self, offset):
        data = self.address_space.read(offset + self.type.offset, self.buffer_size)
        return data[self.type.offset] == "\x06" and data[self.size.offset] == "\x70"

    def skip(self, data, offset):
        try:
            next = data.index("\x06", offset+1)
            return next - self.type.offset - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset
    
class CheckDTBAligned(scan.ScannerCheck):
    """ Checks that _EPROCESS.Pcb.DirectoryTableBase is aligned to 0x20 """
    def check(self, offset):
        eprocess = object2.NewObject("_EPROCESS", vm=self.address_space,
                             offset = offset)
        
        return eprocess.Pcb.DirectoryTableBase[0].v() % 0x20 == 0

class CheckThreadList(scan.ScannerCheck):
    """ Checks that _EPROCESS thread list points to the kernel Address Space """
    def check(self, offset):
        eprocess = object2.NewObject("_EPROCESS", vm=self.address_space,
                             offset = offset)
        kernel = 0x80000000
        
        list_head = eprocess.ThreadListHead

        if list_head.Flink.v() > kernel and \
               list_head.Blink > kernel:
            return True

class CheckSynchronization(scan.ScannerCheck):
    """ Checks that _EPROCESS.WorkingSetLock and _EPROCESS.AddressCreationLock look valid """
    def check(self, offset):
        eprocess = object2.NewObject("_EPROCESS", vm=self.address_space,
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
        ethread = object2.NewObject("_ETHREAD", vm=self.address_space,
                             offset = offset)

        pid = ethread.Cid.UniqueProcess.v()
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
        ethread = object2.NewObject("_ETHREAD", vm=self.address_space,
                            offset = offset)
        
        sem = ethread.Tcb.Timer.Header
        if sem.Type == 0x8 and sem.Size == 0xa:
            return True

class CheckThreadProcess(scan.ScannerCheck):
    """ Check that _ETHREAD.Cid.UniqueProcess is in kernel space """
    kernel = 0x80000000
    def check(self, offset):
        ethread = object2.NewObject("_ETHREAD", vm=self.address_space,
                            offset = offset)
        if ethread.Cid.UniqueProcess == 0 or ethread.ThreadsProcess.v() > self.kernel:
            return True

class CheckThreadStartAddress(scan.ScannerCheck):
    """ Checks that _ETHREAD.StartAddress is not 0 """
    def check(self, offset):
        ethread = object2.NewObject("_ETHREAD", vm=self.address_space,
                            offset = offset)
        if ethread.Cid.UniqueProcess == 0 or ethread.StartAddress.v() != 0:
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
    def render_text(self, outfd, data):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(astype = 'physical')
        start = time.time()
        outfd.write("No.  PID    TID    Offset    \n---- ------ ------ ----------\n")

        for offset in ThreadScan().scan(address_space):
            ethread = object2.NewObject('_ETHREAD', vm=address_space, offset=offset)
            cnt = time.time() - start

            outfd.write("%4d %6d %6d 0x%0.8x\n" % (cnt, ethread.Cid.UniqueProcess,
                                                   ethread.Cid.UniqueThread, offset))
   
class PSScan(scan.BaseScanner):
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

    def render_dot(self, outfd, data):
        address_space = utils.load_as(astype = 'physical')

        objects = set()
        links = set()
        
        for offset in PSScan().scan(address_space):
            eprocess = object2.NewObject('_EPROCESS', vm=address_space, offset=offset)

            label = "%s | %s |" % (eprocess.UniqueProcessId,
                                                 eprocess.ImageFileName)
            if eprocess.ExitTime:
                label += "exited\\n%s" % eprocess.ExitTime
                options = ' style = "filled" fillcolor = "lightgray" '
            else:
                label += "running"
                options = ''

            objects.add('pid%s [label="%s" shape="record" %s];\n' % (eprocess.UniqueProcessId,
                                                             label, options))
            links.add("pid%s -> pid%s [];\n" % (eprocess.InheritedFromUniqueProcessId,
                                              eprocess.UniqueProcessId))

        ## Now write the dot file
        outfd.write("digraph processtree { \ngraph [rankdir = \"TB\"];\n")
        for link in links:
            outfd.write(link)

        for obj in objects:
            outfd.write(obj)
        outfd.write("}")
        
    def render_text(self, outfd, data):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(astype = 'physical')
        start = time.time()
        outfd.write("No.  PID    PPID   Time created             Time exited              Offset     PDB        Remarks\n"+ \
                    "---- ------ ------ ------------------------ ------------------------ ---------- ---------- ----------------\n")
        
        for offset in PSScan().scan(address_space):
            eprocess = object2.NewObject('_EPROCESS', vm=address_space, offset=offset)
            cnt = time.time() - start

            outfd.write("%4d %6d %6d %24s %24s 0x%0.8x 0x%0.8x %-16s\n" % (
                cnt,
                eprocess.UniqueProcessId,
                eprocess.InheritedFromUniqueProcessId,
                eprocess.CreateTime or '',
                eprocess.ExitTime or '',
                eprocess.offset,
                eprocess.Pcb.DirectoryTableBase[0],
                eprocess.ImageFileName))
