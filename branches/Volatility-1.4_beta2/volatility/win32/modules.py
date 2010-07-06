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

import volatility.win32.info as info
import volatility.obj as obj

def lsmod(addr_space):
    """ A Generator for modules (uses _KPCR symbols) """
    ## Locate the kpcr struct - this is hard coded right now
    kpcr = obj.Object("_KPCR", info.kpcr_addr, addr_space)

    ## Try to dereference the KdVersionBlock as a 64 bit struct
    DebuggerDataList = kpcr.KdVersionBlock.dereference_as("_DBGKD_GET_VERSION64").DebuggerDataList

    if DebuggerDataList.is_valid():
        offset = DebuggerDataList.dereference().v()
        ## This is a pointer to a _KDDEBUGGER_DATA64 struct. We only
        ## care about the PsActiveProcessHead entry:
        tmp = obj.Object("_KDDEBUGGER_DATA64", offset,
                        addr_space).PsLoadedModuleList

        if not tmp.is_valid():
            ## Ok maybe its a 32 bit struct
            tmp = obj.Object("_KDDEBUGGER_DATA32", offset,
                            addr_space).PsLoadedModuleList

        ## Try to iterate over the process list in PsActiveProcessHead
        ## (its really a pointer to a _LIST_ENTRY)
        for l in tmp.dereference_as("_LIST_ENTRY").list_of_type(
            "_LDR_MODULE", "InLoadOrderModuleList"):
            yield l