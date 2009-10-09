# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import os

from time import gmtime, strftime
from vutils import get_standard_parser, is_hiberfil, is_crash_dump, types, get_dtb, find_addr_space, load_pae_address_space, load_nopae_address_space, load_and_identify_image, find_dtb
from forensics.addrspace import FileAddressSpace
from forensics.win32.hiber_addrspace import WindowsHiberFileSpace32
from forensics.win32.crash_addrspace import WindowsCrashDumpSpace32
from forensics.win32.tasks import process_addr_space
from forensics.win32.tasks import process_list, process_pid
from forensics.win32.scan import module_scan, conn_scan, ps_scan_dot, ps_scan, socket_scan, thrd_scan
from forensics.win32.crashdump import dd_to_crash
import forensics.win32.meta_info as meta_info
from forensics.win32.scan2 import scan_addr_space, PoolScanProcessDot, PoolScanThreadFast2
from forensics.win32.scan2 import PoolScanProcessFast2 

class VolatoolsModule:
    def __init__(self, cmd_name, cmd_desc, cmd_execute):
        self.cmd_name = cmd_name
        self.cmd_desc = cmd_desc
        self.cmd_execute = cmd_execute


    def desc(self):
        return self.cmd_desc

    def execute(self, module, args):
        self.cmd_execute(module, args)

###################################
#  Datetime
###################################
def format_time(time):
    ts = strftime("%a %b %d %H:%M:%S %Y GMT",
                gmtime(time))
    return ts

###################################
#  strings - identify pid(s) associated with a string
###################################
def print_string(offset, pidlist, string):
    print "%d " % (offset),

    print "[%s:%x" % (pidlist[0][0], pidlist[0][1] | (offset & 0xFFF)),
    
    for i in pidlist[1:]:
        print " %s:%x" % (i[0], (i[1] | (offset & 0xFFF))),

    print "] %s" % string,
    
def get_strings(cmdname, argv):
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--strings', help='(required) File of form <offset>:<string>',
                  action='store', type='string', dest='stringfile')
    opts, _args = op.parse_args(argv)

    if opts.stringfile is None:
        op.error("String file (-s) required")

    try:
        strings = open(opts.stringfile, "r")
    except:
        op.error("Invalid or inaccessible file %s" % opts.stringfile)

    (addr_space, symtab, types) = load_and_identify_image(op, opts)

    all_tasks = process_list(addr_space, types, symtab)

    # dict of form phys_page -> [isKernel, (pid1, vaddr1), (pid2, vaddr2) ...]
    # where isKernel is True or False. if isKernel is true, list is of all kernel addresses
    # ASSUMPTION: no pages mapped in kernel and userland
    reverse_map = {}


    vpage = 0
    while vpage < 0xFFFFFFFF:
        kpage = addr_space.vtop(vpage)
        if not kpage is None:
            if not reverse_map.has_key(kpage):
                reverse_map[kpage] = [True]
            reverse_map[kpage].append(('kernel', vpage))
        vpage += 0x1000

    for task in all_tasks:
        process_id = process_pid(addr_space, types, task)
        process_address_space = process_addr_space(addr_space, types, task, opts.filename)
        vpage = 0
        try:
            while vpage < 0xFFFFFFFF:
                physpage = process_address_space.vtop(vpage)
                if not physpage is None:
                    if not reverse_map.has_key(physpage):
                        reverse_map[physpage] = [False]

                    if not reverse_map[physpage][0]:
                        reverse_map[physpage].append((process_id, vpage))
                vpage += 0x1000
        except:
            continue

    for stringLine in strings:
        (offsetString, string) = stringLine.split(':', 1)
        try:
            offset = int(offsetString)
        except:
            op.error("String file format invalid.")
        if reverse_map.has_key(offset & 0xFFFFF000):
            print_string(offset, reverse_map[offset & 0xFFFFF000][1:], string)

###################################
#  psscan - Scan for EPROCESS objects
###################################

def psscan(cmdname, argv):
    """
    This module scans for EPROCESS objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)

    op.add_option('-d', '--dot',
                  help='Print processes in dot format',
                  action='store_true',dest='dot_format', default=False)

    opts, _args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexadecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexadecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"%(filesize))

    else:
        end = filesize

    try:
        if slow == False:
            flat_address_space = FileAddressSpace(filename, fast=True)
        else:
            flat_address_space = FileAddressSpace(filename, fast=False)
    except:
        op.error("Unable to open image file %s" % (filename))
    
    if is_hiberfil(filename) == True:
        flat_address_space = FileAddressSpace(filename, fast=False)
        flat_address_space = WindowsHiberFileSpace32(flat_address_space, 0, 0)
        slow = True

    if opts.dot_format:
        ps_scan_dot(flat_address_space, types, filename, start, end, slow) 
    else:
        ps_scan(flat_address_space, types, filename, start, end, slow) 

###################################
#  thrdscan - Scan for ETHREAD objects
###################################

def thrdscan(cmdname, argv):
    """
    This module scans for ETHREAD objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)

    opts, _args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexadecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexadecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"% (filesize) )

    else:
        end = filesize

    try:

        if slow == False:
            flat_address_space = FileAddressSpace(filename, fast=True)
        else:
            flat_address_space = FileAddressSpace(filename, fast=False)

    except:
        op.error("Unable to open image file %s" % (filename))
    
    if is_hiberfil(filename) == True:
        flat_address_space = FileAddressSpace(filename, fast=False)
        flat_address_space = WindowsHiberFileSpace32(flat_address_space, 0, 0)
        slow = True

    thrd_scan(flat_address_space, types, filename, start, end, slow) 


###################################
#  sockscan - Scan for socket objects
###################################

def sockscan(cmdname, argv):
    """
    This module scans for socket objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)


    opts, _args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexadecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexadecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x" % (filesize))

    else:
        end = filesize

    try:

        if slow == False:
            flat_address_space = FileAddressSpace(filename, fast=True)
        else:
            flat_address_space = FileAddressSpace(filename, fast=False)

    except:
        op.error("Unable to open image file %s" % (filename))
   
    if is_hiberfil(filename) == True:
        flat_address_space = FileAddressSpace(filename, fast=False)
        flat_address_space = WindowsHiberFileSpace32(flat_address_space, 0, 0)
        slow = True

    socket_scan(flat_address_space, types, filename, start, end, slow) 

###################################
#  connscan - Scan for connection objects
###################################

def connscan(cmdname, argv):
    """
    This module scans for connection objects
    """
    op = get_standard_parser(cmdname)

    op.add_option('-s', '--start',
                  help='Start of scan (in hex)',
                  action='store', type='string', dest='start')

    op.add_option('-e', '--end',
                  help='End of scan (in hex)',
                  action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)

    opts, _args = op.parse_args(argv)

    slow = opts.slow

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename    


    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexadecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexadecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x" % (filesize))

    else:
        end = filesize

    try:

        if slow == False:
            flat_address_space = FileAddressSpace(filename, fast=True)
        else:
            flat_address_space = FileAddressSpace(filename, fast=False)

    except:
        op.error("Unable to open image file %s" % (filename))

    if is_hiberfil(filename) == True:
        flat_address_space = FileAddressSpace(filename, fast=False)
        flat_address_space = WindowsHiberFileSpace32(flat_address_space, 0, 0)
        slow = True
    
    conn_scan(flat_address_space, types, filename, start, end, slow) 

###################################
#  module scan
###################################
        
def modscan(cmdname, argv):
    """
    This (Volatility) module scans for (Windows) modules
    """
    
    op = get_standard_parser(cmdname)
   
    op.add_option('-s', '--start',
        help='Start of scan (in hex)',
        action='store', type='string', dest='start')

    op.add_option('-e', '--end',
        help='End of scan (in hex)',
        action='store', type='string', dest='end')

    op.add_option('-l', '--slow',
                  help='Scan in slow mode',
                  action='store_true',dest='slow', default=False)
    
    opts, _args = op.parse_args(argv)
    
    slow = opts.slow
    
    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  
    
    if not opts.start is None:
        try:
            start = int(opts.start, 16)
        except:
            op.error("Start of scan must be a hexadecimal number.")
    else:
        start = 0

    filesize = os.path.getsize(filename)

    if not opts.end is None:
        try:
            end = int(opts.end, 16)
        except:
            op.error("End of scan must be a hexadecimal number.")

        if end > filesize:
            op.error("End of scan is larger than filesize 0x%x"%(filesize))
    else:
        end = filesize
       
    try:  
        flat_address_space = FileAddressSpace(filename, fast=True)
    except:
        op.error("Unable to open image file %s" % (filename))
 
    # Find a dtb value
    if opts.base is None:
        sysdtb = find_dtb(flat_address_space, types)
    else:
        try:
            sysdtb = int(opts.base, 16)
        except:
            op.error("Directory table base must be a hexadecimal number.")


    if is_crash_dump(filename) == True:
        sub_addr_space = WindowsCrashDumpSpace32(flat_address_space, 0, 0)
    else:
        sub_addr_space = flat_address_space

    if is_hiberfil(filename) == True:
        flat_address_space = FileAddressSpace(filename, fast=False)
        flat_address_space = WindowsHiberFileSpace32(flat_address_space, 0, 0)
        slow = True

    meta_info.set_dtb(sysdtb)
    kaddr_space = load_pae_address_space(filename, sysdtb)
    if kaddr_space is None:
        kaddr_space = load_nopae_address_space(filename, sysdtb)
    meta_info.set_kas(kaddr_space)

    module_scan(flat_address_space, types, filename, start, end, slow) 

###################################
#  raw2dmp - raw2dump raw image to crash dump
###################################
def raw2dmp(cmdname, argv):
    """
    This module generates a crash dump from a image of ram
    """
    op = get_standard_parser(cmdname)
    
    op.add_option('-o', '--output', help='Output file',
                  action='store', type='string', dest='outfile')

    opts, _args = op.parse_args(argv)

    if (opts.outfile is None):
        op.error("Output file is required")  

    (addr_space, symtab, types) = load_and_identify_image(op, opts)
        
    dd_to_crash(addr_space, types, symtab, opts)

def thrdscan2(cmdname, argv):
    scanners = []
    op = get_standard_parser(cmdname)
    opts, _args = op.parse_args(argv)

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  

    try:
        flat_address_space = FileAddressSpace(filename, fast=True)
    except:
        op.error("Unable to open image file %s" % (filename))
    
    meta_info.set_datatypes(types)

    # Determine the applicable address space
    search_address_space = find_addr_space(flat_address_space, types)

    # Find a dtb value
    if opts.base is None:
        sysdtb = get_dtb(search_address_space, types)
    else:
        try:
            sysdtb = int(opts.base, 16)
        except:
            op.error("Directory table base must be a hexadecimal number.")

    meta_info.set_dtb(sysdtb)
    kaddr_space = load_pae_address_space(filename, sysdtb)
    if kaddr_space is None:
        kaddr_space = load_nopae_address_space(filename, sysdtb)
    meta_info.set_kas(kaddr_space)

    print "No.  PID    TID    Offset    \n"+ \
          "---- ------ ------ ----------\n"

    scanners.append((PoolScanThreadFast2(search_address_space)))
    scan_addr_space(search_address_space, scanners)

def psscan2(cmdname, argv):
    scanners = []
    op = get_standard_parser(cmdname)
    op.add_option('-d', '--dot',
        help='Print processes in dot format',
        action='store_true', dest='dot_format', default=False)
    opts, _args = op.parse_args(argv)

    if (opts.filename is None) or (not os.path.isfile(opts.filename)) :
        op.error("File is required")
    else:
        filename = opts.filename  

    try:
        flat_address_space = FileAddressSpace(filename, fast=True)
    except:
        op.error("Unable to open image file %s" % (filename))


    meta_info.set_datatypes(types)

    # Determine the applicable address space
    search_address_space = find_addr_space(flat_address_space, types)

    # Find a dtb value
    if opts.base is None:
        sysdtb = get_dtb(search_address_space, types)
    else:
        try:
            sysdtb = int(opts.base, 16)
        except:
            op.error("Directory table base must be a hexadecimal number.")

    meta_info.set_dtb(sysdtb)
    kaddr_space = load_pae_address_space(filename, sysdtb)
    if kaddr_space is None:
        kaddr_space = load_nopae_address_space(filename, sysdtb)
    meta_info.set_kas(kaddr_space)

    if opts.dot_format:
        print "digraph processtree { \n" + \
              "graph [rankdir = \"TB\"];"
        scanners.append((PoolScanProcessDot(search_address_space)))
    else:
        print "PID    PPID   Time created             Time exited              Offset     PDB        Remarks\n" + \
          "------ ------ ------------------------ ------------------------ ---------- ---------- ----------------\n"
        scanners.append((PoolScanProcessFast2(search_address_space)))

    scan_addr_space(search_address_space, scanners)

    if opts.dot_format:
        print "}"
