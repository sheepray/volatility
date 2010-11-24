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
import volatility.plugins.kpcrscan as kpcr
import volatility.timefmt as timefmt
import volatility.obj as obj

## The following is a conversion of basic C99 types to python struct
## format strings. NOTE: since volatility is analysing images which
## are not necessarily the same bit size as the currently running
## platform you may not use platform specific format specifiers here
## like l or L - you must use i or I.
x86_native_types_32bit = { \
    'int' : [4, 'i'], \
    'long': [4, 'i'], \
    'unsigned long' : [4, 'I'], \
    'unsigned int' : [4, 'I'], \
    'address' : [4, 'I'], \
    'char' : [1, 'c'], \
    'unsigned char' : [1, 'B'], \
    'unsigned short int' : [2, 'H'], \
    'unsigned short' : [2, 'H'], \
    'unsigned be short' : [2, '>H'], \
    'short' : [2, 'h'], \
    'long long' : [8, 'q'], \
    'unsigned long long' : [8, 'Q'], \
    }

class AbstractWindows(obj.Profile):
    """ A Profile for Windows systems """
    native_types = x86_native_types_32bit

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
            data = self.vm.read(self.Buffer.v(), length)
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

        offset = self.profile.get_obj_offset(type, member)

        seen = set()
        seen.add(lst.v_offset)

        while 1:
            ## Instantiate the object
            item = obj.Object(type, offset = lst.v_offset - offset,
                                    vm = self.vm,
                                    parent = self.v_parent,
                                    name = type)


            if forward:
                lst = item.m(member).Flink.dereference()
            else:
                lst = item.m(member).Blink.dereference()

            if not lst.is_valid() or lst.v_offset in seen:
                return
            seen.add(lst.v_offset)

            yield item

    def __nonzero__(self):
        ## List entries are valid when both Flinks and Blink are valid
        return bool(self.Flink) or bool(self.Blink)

    def __iter__(self):
        return self.list_of_type(self.v_parent.name, self.name)

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
        dt = datetime.datetime.utcfromtimestamp(self.v())
        if self.is_utc:
            # Only do dt.replace when dealing with UTC
            dt = dt.replace(tzinfo = timefmt.UTC())
        return dt

    def __format__(self, formatspec):
        """Formats the datetime according to the timefmt module"""
        dt = self.as_datetime()
        return format(timefmt.display_datetime(dt), formatspec)

AbstractWindows.object_classes['WinTimeStamp'] = WinTimeStamp


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
        for val in scanner.scan(self.vm):
            yield val

AbstractWindows.object_classes['VolatilityKPCR'] = VolatilityKPCR
