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

import os, pdb
from forensics.win32.scan2 import PoolScanner
import forensics.commands
import forensics.conf
config = forensics.conf.ConfObject()
import forensics.utils as utils
from forensics.object2 import NewObject


class PoolScanFile(PoolScanner):
    pool_size = 0x98
    pool_tag = "Fil\xe5"
    
    def __init__(self):
        PoolScanner.__init__(self)
        self.add_constraint(self.check_blocksize_geq)
        self.add_constraint(self.check_pooltype_nonpaged)
        self.add_constraint(self.check_poolindex_zero)

class filescan2(forensics.commands.command):
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
    
    def execute(self):
        ## Just grab the AS and scan it using our scanner
        address_space = utils.load_as(dict(type='physical'))

        ## Will need the kernel AS for later:
        self.kernel_address_space = utils.load_as()

        for offset in PoolScanFile().scan(address_space):
            print offset

class PoolScanFileXXXX:
    """ Scan for pool objects """
    def __init__(self,addr_space):
        GenMemScanObject.__init__(self, addr_space)
        self.pool_tag = "\x46\x69\x6c\xe5"
        self.pool_size = 0x98

    class Scan(PoolScanner):
        def __init__(self, poffset, outer):
            PoolScanner.__init__(self, poffset, outer)
            self.kas = meta_info.KernelAddressSpace
            # add constraints
            self.add_constraint(self.check_pooltype_nonpaged)
            self.add_constraint(self.check_poolindex_zero)
            self.add_constraint(self.check_blocksize_geq)

        def object_offset(self,found):
            return found - 4 + obj_size(self.data_types, \
                '_POOL_HEADER')

        def object_action(self,buff,object_offset):
            AllocSize = self.get_poolsize(buff, object_offset-4)
         
            # build structure from higher to lower addresses            
            SizeOfFile = obj_size(self.data_types, '_FILE_OBJECT')
            StartOfFile = object_offset - 8 + AllocSize - SizeOfFile
            Name = read_unicode_string_buf(buff, self.kas, self.data_types, \
                ['_FILE_OBJECT', 'FileName'], StartOfFile)
            # unclutter the output
            if ((Name == None) or (Name == '')):
                return False
                        
            def _check_access(self,buff,member,indicator,offset):
                if (read_obj_from_buf(buff, self.data_types, \
                    ['_FILE_OBJECT', member], StartOfFile) > 0):
                        return indicator
                else:
                    return '-'
                
            AccessStr =  _check_access(self, buff, \
                'ReadAccess', 'R', StartOfFile)
            AccessStr += _check_access(self, buff, \
                'WriteAccess', 'W', StartOfFile)
            AccessStr += _check_access(self, buff, \
                'DeleteAccess', 'D', StartOfFile)
            AccessStr += _check_access(self, buff, \
                'SharedRead', 'r', StartOfFile)
            AccessStr += _check_access(self, buff, \
                'SharedWrite', 'w', StartOfFile)
            AccessStr += _check_access(self, buff, \
                'SharedDelete', 'd', StartOfFile)
     

            SizeOfObjectHeader = obj_size(self.data_types, '_OBJECT_HEADER')            
            StartOfObjectHeader = StartOfFile - SizeOfObjectHeader
            ObjType = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'Type'], \
                StartOfObjectHeader)
            if ((ObjType == None) or (ObjType == 0xbad0b0b0)):
                return False
            Pointers = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'PointerCount'], \
                StartOfObjectHeader)
            Handles = read_obj_from_buf(buff, self.data_types, \
                ['_OBJECT_HEADER', 'HandleCount'], \
                StartOfObjectHeader)    
                
            address = self.as_offset + object_offset
            
            print "0x%08x 0x%08x %4d %4d %6s %s" % \
                (address, ObjType, Pointers, Handles, AccessStr, Name)


class fileobjscan(forensics.commands.command):

    # Declare meta information associated with this plugin

    meta_info = forensics.commands.command.meta_info
    meta_info['author'] = 'Andreas Schuster'
    meta_info['copyright'] = 'Copyright (c) 2009 Andreas Schuster'
    meta_info['contact'] = 'a.schuster@forensikblog.de'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://computer.forensikblog.de/en/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '0.1'

    def help(self):
        return  "Scan for file objects"

    def execute(self):
        op = self.op
        opts = self.opts
           
        (addr_space, symtab, types) = load_and_identify_image(op, opts)
        
        # merge type information and make it globally accessible
        types.update(extra_types)
        set_datatypes(types)
        
        if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
            op.error("File is required")
        else:
            filename = opts.filename 
                     
        try:
            flat_addr_space = FileAddressSpace(filename, fast=True)
        except:
            op.error("Unable to open image file %s" %(filename))
            
        # find initial Directory Table Base (CR3)
        if opts.base is None:
            sysdtb = find_dtb(flat_addr_space, types)
        else:
            try:
                sysdtb = int(opts.base, 16)
            except:
                op.error("Directory table base must be a hexidecimal number.")
        set_dtb(sysdtb)

        # build kernel address space in either PAE or non-PAE mode        
        kaddr_space = load_pae_address_space(filename, sysdtb)
        if kaddr_space is None:
            kaddr_space = load_nopae_address_space(filename, sysdtb)
        set_kas(kaddr_space)
                     
        search_addr_space = find_addr_space(flat_addr_space, types)
        scanners = []
        scanners.append((PoolScanFile(search_addr_space)))
        
        print "%-10s %-10s %4s %4s %6s %s" % \
            ('Phys.Addr.', 'Obj Type', '#Ptr', '#Hnd', 'Access',\
            'Name')
        scan_addr_space(search_addr_space, scanners)
