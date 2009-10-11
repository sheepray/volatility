#!/usr/bin/env python
#
#       fileobjscan.py
#       
#       Copyright 2009 Andreas Schuster <a.schuster@yendor.net>
#       
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.

"""
@author:       Andreas Schuster
@license:      GNU General Public License 2.0 or later
@contact:      a.schuster@forensikblog.de
@organization: http://computer.forensikblog.de/en/
"""

import volatility.win32.scan2 as scan2
import volatility.commands as commands
import volatility.debug as debug
import volatility.conf
config = volatility.conf.ConfObject()
import volatility.utils as utils
import volatility.object2 as object2

class PoolScanFile(scan2.PoolScanner):
    ## We dont want any preamble - the offsets should be those of the
    ## _POOL_HEADER directly.
    preamble = []
    checks = [ ('PoolTagCheck', dict(tag = "Fil\xe5")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x98)),
               ('CheckPoolType', dict(non_paged = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class filescan2(commands.command):
    """ Scan Physical memory for _FILE_OBJECT pool allocations
    """
    # Declare meta information associated with this plugin
    meta_info = {}
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.1'

    def parse_string(self, unicode_obj):
        ## We need to do this because the unicode_obj buffer is in
        ## kernel_address_space
        string_length = unicode_obj.Length.v()
        string_offset = unicode_obj.Buffer.v()            

        string = self.kernel_address_space.read(string_offset, string_length)
        if not string: return ''
        return string[:255].decode("utf16","ignore").encode("utf8","ignore")

    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(astype='physical')

        ## Will need the kernel AS for later:
        self.kernel_address_space = utils.load_as()

        for offset in PoolScanFile().scan(address_space):
            pool_obj = object2.NewObject("_POOL_HEADER", vm=address_space,
                                 offset = offset)
            
            ## We work out the _FILE_OBJECT from the end of the
            ## allocation (bottom up).
            file_obj = object2.NewObject("_FILE_OBJECT", vm=address_space,
                                 offset = offset + pool_obj.BlockSize * 8 - \
                                 address_space.profile.get_obj_size("_FILE_OBJECT")
                                 )

            ## The _OBJECT_HEADER is immediately below the _FILE_OBJECT
            object_obj = object2.NewObject("_OBJECT_HEADER", vm=address_space,
                                   offset = file_obj.offset - \
                                   address_space.profile.get_obj_size("_OBJECT_HEADER")
                                   )

            ## Skip unallocated objects
            if object_obj.Type == 0xbad0b0b0:
                continue

            Name = self.parse_string(file_obj.FileName)
            ## If the string is not reachable we skip it
            if not Name: continue

            yield (object_obj, file_obj, Name)

    def render_text(self, outfd, data):
        outfd.write("%-10s %-10s %4s %4s %6s %s\n" % \
                    ('Phys.Addr.', 'Obj Type', '#Ptr', '#Hnd', 'Access',\
                     'Name'))

        for object_obj, file_obj, Name in data:
            ## Make a nicely formatted ACL string
            AccessStr = ((file_obj.ReadAccess > 0 and "R") or '-') + \
                        ((file_obj.WriteAccess > 0  and "W") or '-') + \
                        ((file_obj.DeleteAccess > 0 and "D") or '-') + \
                        ((file_obj.SharedRead > 0 and "r") or '-') + \
                        ((file_obj.SharedWrite > 0 and "w") or '-') + \
                        ((file_obj.SharedDelete > 0 and "d") or '-')

            outfd.write("0x%08x 0x%08x %4d %4d %6s %s\n" % \
                        (object_obj.offset, object_obj.Type, object_obj.PointerCount,
                         object_obj.HandleCount, AccessStr, Name))
