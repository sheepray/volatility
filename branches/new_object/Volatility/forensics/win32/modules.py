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
@author:       AAron Walters and Nick Petroni
@license:      GNU General Public License 2.0 or later
@contact:      awalters@komoku.com, npetroni@komoku.com
@organization: Komoku, Inc.
"""

#pylint: disable-msg=C0111

from forensics.object import read_obj, read_unicode_string
from forensics.win32.info import kpcr_addr
from forensics.object2 import NewObject

def lsmod(addr_space):
    """ A Generator for modules (uses _KPCR symbols) """
    ## Locate the kpcr struct - this is hard coded right now
    kpcr = NewObject("_KPCR", kpcr_addr, addr_space)

    ## Try to dereference the KdVersionBlock as a 64 bit struct
    DebuggerDataList = kpcr.KdVersionBlock.dereference_as("_DBGKD_GET_VERSION64").DebuggerDataList

    if DebuggerDataList.is_valid():
        offset = DebuggerDataList.dereference().v()
        ## This is a pointer to a _KDDEBUGGER_DATA64 struct. We only
        ## care about the PsActiveProcessHead entry:
        tmp = NewObject("_KDDEBUGGER_DATA64", offset,
                        addr_space).PsLoadedModuleList

        if not tmp.is_valid():
            ## Ok maybe its a 32 bit struct
            tmp = NewObject("_KDDEBUGGER_DATA32", offset,
                            addr_space).PsLoadedModuleList

        ## Try to iterate over the process list in PsActiveProcessHead
        ## (its really a pointer to a _LIST_ENTRY)
        for l in tmp.dereference_as("_LIST_ENTRY").list_of_type(
            "_LDR_MODULE", "InLoadOrderModuleList"):
            yield l

def module_imagename(address_space, types, module_vaddr):
    return read_unicode_string(address_space, types,
        ['_LDR_DATA_TABLE_ENTRY', 'FullDllName'], module_vaddr)

def module_modulename(address_space, types, module_vaddr):
    return read_unicode_string(address_space, types,
        ['_LDR_DATA_TABLE_ENTRY', 'BaseDllName'], module_vaddr)

def module_imagesize(address_space, types, module_vaddr):
    return read_obj(address_space, types,
        ['_LDR_DATA_TABLE_ENTRY', 'SizeOfImage'], module_vaddr)

def module_baseaddr(address_space, types, module_vaddr):
    return read_obj(address_space, types,
        ['_LDR_DATA_TABLE_ENTRY', 'DllBase'], module_vaddr)

def module_find_baseaddr(addr_space, types, modules, name):
    for module in modules:
        module_name = module_imagename(addr_space, types, module)
        if module_name is None:
            continue

        if module_name.find(name) != -1:
            return module_baseaddr(addr_space, types, module)
