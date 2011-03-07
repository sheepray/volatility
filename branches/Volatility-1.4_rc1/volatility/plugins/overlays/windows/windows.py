# Volatility
# Copyright (c) 2008 Volatile Systems
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

import datetime
import socket, struct
import volatility.plugins.overlays.basic as basic
import volatility.plugins.kpcrscan as kpcr
import volatility.plugins.kdbgscan as kdbg
import volatility.timefmt as timefmt
import volatility.obj as obj

class AbstractWindows(obj.Profile):
    """ A Profile for Windows systems """
    native_types = basic.x86_native_types_32bit

class _UNICODE_STRING(obj.CType):
    """Class representing a _UNICODE_STRING

    Adds the following behavior:
      * The Buffer attribute is presented as a Python string rather
        than a pointer to an unsigned short.
      * The __str__ method returns the value of the Buffer.
    """
    def v(self):
        try:
            length = self.Length.v()
            if length > 1024:
                length = 0
            data = self.obj_vm.read(self.Buffer.v(), length)
            return data.decode("utf16", "ignore").encode("ascii", 'backslashreplace')
        except Exception, _e:
            return ''

    def __nonzero__(self):
        ## Unicode strings are valid if they point at a valid memory
        return bool(self.Buffer)

    def __format__(self, formatspec):
        return format(self.v(), formatspec)

    def __str__(self):
        return self.v()

AbstractWindows.object_classes['_UNICODE_STRING'] = _UNICODE_STRING

class _LIST_ENTRY(obj.CType):
    """ Adds iterators for _LIST_ENTRY types """
    def list_of_type(self, type, member, forward = True):
        if not self.is_valid():
            return

        ## Get the first element
        if forward:
            lst = self.Flink.dereference()
        else:
            lst = self.Blink.dereference()

        offset = self.obj_vm.profile.get_obj_offset(type, member)

        seen = set()
        seen.add(lst.obj_offset)

        while 1:
            ## Instantiate the object
            item = obj.Object(type, offset = lst.obj_offset - offset,
                                    vm = self.obj_vm,
                                    parent = self.obj_parent,
                                    name = type)


            if forward:
                lst = item.m(member).Flink.dereference()
            else:
                lst = item.m(member).Blink.dereference()

            if not lst.is_valid() or lst.obj_offset in seen:
                return
            seen.add(lst.obj_offset)

            yield item

    def __nonzero__(self):
        ## List entries are valid when both Flinks and Blink are valid
        return bool(self.Flink) or bool(self.Blink)

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_name, self.obj_name)

AbstractWindows.object_classes['_LIST_ENTRY'] = _LIST_ENTRY

class WinTimeStamp(obj.NativeType):

    def __init__(self, theType = None, offset = None, vm = None,
                 parent = None, name = None, is_utc = False, **args):
        self.is_utc = is_utc
        obj.NativeType.__init__(self, theType, offset, vm, parent = parent,
                                name = name, format_string = "q")

    def windows_to_unix_time(self, windows_time):
        """
        Converts Windows 64-bit time to UNIX time

        @type  windows_time:  Integer
        @param windows_time:  Windows time to convert (64-bit number)

        @rtype  Integer
        @return  UNIX time
        """
        if(windows_time == 0):
            unix_time = 0
        else:
            unix_time = windows_time / 10000000
            unix_time = unix_time - 11644473600

        if unix_time < 0:
            unix_time = 0

        return unix_time

    def as_windows_timestamp(self):
        return obj.NativeType.v(self)

    def v(self):
        value = self.as_windows_timestamp()
        return self.windows_to_unix_time(value)

    def __nonzero__(self):
        return self.v() != 0

    def __str__(self):
        return "{0}".format(self)

    def as_datetime(self):
        try:
            dt = datetime.datetime.utcfromtimestamp(self.v())
            if self.is_utc:
                # Only do dt.replace when dealing with UTC
                dt = dt.replace(tzinfo = timefmt.UTC())
        except ValueError, e:
            return obj.NoneObject("Datetime conversion failure: " + str(e))
        return dt

    def __format__(self, formatspec):
        """Formats the datetime according to the timefmt module"""
        dt = self.as_datetime()
        if dt != None:
            return format(timefmt.display_datetime(dt), formatspec)
        return "-"

AbstractWindows.object_classes['WinTimeStamp'] = WinTimeStamp

class _EPROCESS(obj.CType):
    """ An extensive _EPROCESS with bells and whistles """
    def _Peb(self, _attr):
        """ Returns a _PEB object which is using the process address space.

        The PEB structure is referencing back into the process address
        space so we need to switch address spaces when we look at
        it. This method ensure this happens automatically.
        """
        process_ad = self.get_process_address_space()
        if process_ad:
            offset = self.m("Peb").v()
            peb = obj.Object("_PEB", offset, vm = process_ad,
                                    name = "Peb", parent = self)

            if peb.is_valid():
                return peb

        return obj.NoneObject("Peb not found")

    def get_process_address_space(self):
        """ Gets a process address space for a task given in _EPROCESS """
        directory_table_base = self.Pcb.DirectoryTableBase.v()

        try:
            process_as = self.obj_vm.__class__(self.obj_vm.base, self.obj_vm.get_config(), dtb = directory_table_base)
        except AssertionError, _e:
            return obj.NoneObject("Unable to get process AS")

        process_as.name = "Process {0}".format(self.UniqueProcessId)

        return process_as

AbstractWindows.object_classes['_EPROCESS'] = _EPROCESS

class _HANDLE_TABLE(obj.CType):
    """ A class for _HANDLE_TABLE. 
    
    This used to be a member of _EPROCESS but it was isolated per issue 
    91 so that it could be subclassed and used to service other handle 
    tables, such as the _KDDEBUGGER_DATA64.PspCidTable.
    """
    
    def get_item(self, offset):
        return obj.Object("_OBJECT_HEADER", offset, self.obj_vm,
                                            parent = self)
    
    def _make_handle_array(self, offset, level):
        """ Returns an array of _HANDLE_TABLE_ENTRY rooted at offset,
        and iterates over them.

        """
        if level > 0:
            count = 0x400
            targetType = "unsigned int"
        else:
            count = 0x200
            targetType = "_HANDLE_TABLE_ENTRY"

        table = obj.Object("Array", offset = offset, vm = self.obj_vm, count = count,
                           targetType = targetType, parent = self)

        if table:
            for entry in table:
                if not entry.is_valid():
                    break

                if level > 0:
                    ## We need to go deeper:
                    for h in self._make_handle_array(entry, level - 1):
                        yield h
                else:
                    ## OK We got to the bottom table, we just resolve
                    ## objects here:
                    offset = int(entry.Object.v()) & ~0x00000007
                                        
                    item = self.get_item(offset)
                    
                    try:
                        # New object header
                        if item.TypeIndex != 0x0:
                            yield item
                    except AttributeError:
                        if item.Type.Name:
                            yield item

    def handles(self):
        """ A generator which yields this process's handles

        _HANDLE_TABLE tables are multi-level tables at the first level
        they are pointers to second level table, which might be
        pointers to third level tables etc, until the final table
        contains the real _OBJECT_HEADER table.

        This generator iterates over all the handles recursively
        yielding all handles. We take care of recursing into the
        nested tables automatically.
        """
        
        LEVEL_MASK = 0xfffffff8
        
        TableCode = self.TableCode.v() & LEVEL_MASK
        table_levels = self.TableCode.v() & ~LEVEL_MASK
        offset = TableCode

        for h in self._make_handle_array(offset, table_levels):
            yield h

AbstractWindows.object_classes['_HANDLE_TABLE'] = _HANDLE_TABLE

## This is an object which provides access to the VAD tree.
class _MMVAD(obj.CType):
    ## parent is the containing _EPROCESS right now
    def __new__(cls, theType, offset, vm, parent, **args):
        ## Find the tag (4 bytes below the current offset). This can
        ## not have ourselves as a target.
        switch = {"Vadl": '_MMVAD_LONG',
                  'VadS': '_MMVAD_SHORT',
                  'Vad ': '_MMVAD_LONG',
                  'VadF': '_MMVAD_SHORT',
                  'Vadm': '_MMVAD_LONG',
                  }

        ## All VADs are done in the process AS - so we might need to
        ## switch Address spaces now. We do this by instantiating an
        ## _EPROCESS over our parent, and having it give us the
        ## correct AS
        if vm.name.startswith("Kernel"):
            eprocess = obj.Object("_EPROCESS", offset = parent.obj_offset, vm = vm)
            vm = eprocess.get_process_address_space()
            if not vm:
                return vm

        ## What type is this struct?
        tag = vm.read(offset - 4, 4)
        theType = switch.get(tag)

        if not theType:
            return obj.NoneObject("Tag {0} not knowns".format(tag))

        ## Note that since we were called from __new__ we can return a
        ## completely different object here (including
        ## NoneObject). This also means that we can not add any
        ## specialist methods to the _MMVAD class.
        result = obj.Object(theType, offset = offset, vm = vm, parent = parent, **args)
        result.newattr('Tag', tag)

        return result

AbstractWindows.object_classes['_MMVAD'] = _MMVAD

class _MMVAD_SHORT(obj.CType):
    def traverse(self, visited = None):
        """ Traverse the VAD tree by generating all the left items,
        then the right items.

        We try to be tolerant of cycles by storing all offsets visited.
        """
        if visited == None:
            visited = set()

        ## We try to prevent loops here
        if self.obj_offset in visited:
            return

        yield self

        for c in self.LeftChild.traverse(visited = visited):
            visited.add(c.obj_offset)
            yield c

        for c in self.RightChild.traverse(visited = visited):
            visited.add(c.obj_offset)
            yield c

    def get_parent(self):
        return self.Parent

    def get_control_area(self):
        return self.ControlArea

    def get_file_object(self):
        return self.ControlArea.FilePointer

class _MMVAD_LONG(_MMVAD_SHORT):
    pass

AbstractWindows.object_classes['_MMVAD_SHORT'] = _MMVAD_SHORT
AbstractWindows.object_classes['_MMVAD_LONG'] = _MMVAD_LONG

class ThreadCreateTimeStamp(WinTimeStamp):

    def __init__(self, *args, **kwargs):
        WinTimeStamp.__init__(self, *args, **kwargs)

    def as_windows_timestamp(self):
        return obj.NativeType.v(self) >> 3

AbstractWindows.object_classes['ThreadCreateTimeStamp'] = ThreadCreateTimeStamp

class _TCPT_OBJECT(obj.CType):
    def _RemoteIpAddress(self, attr):
        return socket.inet_ntoa(struct.pack("<I", self.m(attr).v()))

    def _LocalIpAddress(self, attr):
        return socket.inet_ntoa(struct.pack("<I", self.m(attr).v()))

AbstractWindows.object_classes['_TCPT_OBJECT'] = _TCPT_OBJECT

class VolatilityKPCR(obj.VolatilityMagic):

    def generate_suggestions(self):
        scanner = kpcr.KPCRScanner()
        for val in scanner.scan(self.obj_vm):
            yield val

AbstractWindows.object_classes['VolatilityKPCR'] = VolatilityKPCR

class VolatilityKDBG(obj.VolatilityMagic):

    def generate_suggestions(self):
        volmag = obj.Object('VOLATILITY_MAGIC', offset = 0, vm = self.obj_vm)

        scanner = kdbg.KDBGScanner(needles = [volmag.KDBGHeader.v()])
        for val in scanner.scan(self.obj_vm):
            yield val

AbstractWindows.object_classes['VolatilityKDBG'] = VolatilityKDBG

