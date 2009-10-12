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

import volatility.scan as scan
import volatility.commands as commands
import volatility.debug as debug
import volatility.conf
config = volatility.conf.ConfObject()
import volatility.utils as utils
import volatility.obj as obj

class PoolScanFile(scan.PoolScanner):
    ## We dont want any preamble - the offsets should be those of the
    ## _POOL_HEADER directly.
    preamble = []
    checks = [ ('PoolTagCheck', dict(tag = "Fil\xe5")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x98)),
               ('CheckPoolType', dict(non_paged = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class filescan(commands.command):
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
            pool_obj = obj.Object("_POOL_HEADER", vm=address_space,
                                 offset = offset)
            
            ## We work out the _FILE_OBJECT from the end of the
            ## allocation (bottom up).
            file_obj = obj.Object("_FILE_OBJECT", vm=address_space,
                                 offset = offset + pool_obj.BlockSize * 8 - \
                                 address_space.profile.get_obj_size("_FILE_OBJECT")
                                 )

            ## The _OBJECT_HEADER is immediately below the _FILE_OBJECT
            object_obj = obj.Object("_OBJECT_HEADER", vm=address_space,
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

class PoolScanDriver(PoolScanFile):
    """ Scanner for _DRIVER_OBJECT """
    ## No preamble
    checks = [ ('PoolTagCheck', dict(tag = "Dri\xf6")),
               ('CheckPoolSize', dict(condition = lambda x: x == 0xf8)),
               ('CheckPoolType', dict(non_paged = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]

class driverscan(filescan):
    "Scan for driver objects _DRIVER_OBJECT "
    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(astype='physical')

        ## Will need the kernel AS for later:
        self.kernel_address_space = utils.load_as()

        for offset in PoolScanDriver().scan(address_space):
            pool_obj = obj.Object("_POOL_HEADER", vm=address_space,
                                 offset = offset)
            
            ## We work out the _DRIVER_OBJECT from the end of the
            ## allocation (bottom up).
            extension_obj = obj.Object(
                "_DRIVER_EXTENSION", vm=address_space,
                offset = offset + pool_obj.BlockSize * 8 - 4 -\
                address_space.profile.get_obj_size("_DRIVER_EXTENSION"))
            
            ## The _DRIVER_OBJECT is immediately below the _DRIVER_EXTENSION
            driver_obj = obj.Object(
                "_DRIVER_OBJECT", vm=address_space,
                offset = extension_obj.offset - \
                address_space.profile.get_obj_size("_DRIVER_OBJECT")
                )

            ## The _OBJECT_HEADER is immediately below the _DRIVER_OBJECT
            object_obj = obj.Object(
                "_OBJECT_HEADER", vm=address_space,
                offset = driver_obj.offset - \
                address_space.profile.get_obj_size("_OBJECT_HEADER")
                )

            ## Skip unallocated objects
            if object_obj.Type == 0xbad0b0b0:
                continue

            ## Now we need to work out the _OBJECT_NAME_INFO object
            object_name_info_obj = obj.Object("_OBJECT_NAME_INFO", vm=address_space,
                                                 offset = object_obj.offset - \
                                                 object_obj.NameInfoOffset.v()
                                                 )
            
            yield (object_obj, driver_obj, extension_obj, object_name_info_obj)

        
    def render_text(self, outfd, data):
        print "%-10s %-10s %4s %4s %-10s %6s %-20s %s" % \
              ('Phys.Addr.', 'Obj Type', '#Ptr', '#Hnd', \
               'Start', 'Size', 'Service key', 'Name')
        
        for object_obj, driver_obj, extension_obj, object_name_info_obj in data:
            print "0x%08x 0x%08x %4d %4d 0x%08x %6d %-20s %-12s %s" % \
                  (driver_obj.offset, object_obj.Type, object_obj.PointerCount,
                   object_obj.HandleCount,
                   driver_obj.DriverStart, driver_obj.DriverSize,\
                   self.parse_string(extension_obj.ServiceKeyName),
                   self.parse_string(object_name_info_obj.Name),
                   self.parse_string(driver_obj.DriverName))

class PoolScanMutant(PoolScanDriver):
    """ Scanner for Mutants _KMUTANT """
    checks = [ ('PoolTagCheck', dict(tag = "Mut\xe1")),
               ('CheckPoolSize', dict(condition = lambda x: x >= 0x40)),
               ('CheckPoolType', dict(non_paged = True)),
               ('CheckPoolIndex', dict(value = 0)),
               ]


class mutantscan(filescan):
    "Scan for mutant objects _KMUTANT "
    def __init__(self):
        config.add_option("SILENT", short_option='s', default=False,
                          action='store_true', help='suppress less meaningful results')
        filescan.__init__(self)

    def calculate(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(astype='physical')

        ## Will need the kernel AS for later:
        self.kernel_address_space = utils.load_as()

        for offset in PoolScanMutant().scan(address_space):
            pool_obj = obj.Object("_POOL_HEADER", vm=address_space,
                                 offset = offset)
            
            ## We work out the _DRIVER_OBJECT from the end of the
            ## allocation (bottom up).
            mutant = obj.Object(
                "_KMUTANT", vm=address_space,
                offset = offset + pool_obj.BlockSize * 8 -\
                address_space.profile.get_obj_size("_KMUTANT"))
            
            ## The _OBJECT_HEADER is immediately below the _KMUTANT
            object_obj = obj.Object(
                "_OBJECT_HEADER", vm=address_space,
                offset = mutant.offset - \
                address_space.profile.get_obj_size("_OBJECT_HEADER")
                )

            ## Skip unallocated objects
            ##if object_obj.Type == 0xbad0b0b0:
            ##   continue

            ## Now we need to work out the _OBJECT_NAME_INFO object
            object_name_info_obj = obj.Object("_OBJECT_NAME_INFO", vm=address_space,
                                                     offset = object_obj.offset - \
                                                     object_obj.NameInfoOffset.v()
                                                     )

            if config.SILENT:
                if object_obj.NameInfoOffset == 0:
                    continue
            
            yield (object_obj, mutant, object_name_info_obj)

        
    def render_text(self, outfd, data):
        print "%-10s %-10s %4s %4s %6s %-10s %-10s %s" % \
              ('Phys.Addr.', 'Obj Type', '#Ptr', '#Hnd', 'Signal',\
               'Thread', 'CID', 'Name')
        
        for object_obj, mutant, object_name_info_obj in data:
            if mutant.OwnerThread.v() > 0x80000000:
                thread = obj.Object("_ETHREAD", vm = self.kernel_address_space,
                                   offset = mutant.OwnerThread.v())
                CID = "%s:%s" % (thread.Cid.UniqueProcess, thread.Cid.UniqueThread)
            else:
                CID = ""
            
            print "0x%08x 0x%08x %4d %4d %6d 0x%08x %-10s %s" % \
                  (mutant.offset, object_obj.Type, object_obj.PointerCount,
                   object_obj.HandleCount, mutant.Header.SignalState, \
                   mutant.OwnerThread.v(), CID,
                   self.parse_string(object_name_info_obj.Name)
                   )
