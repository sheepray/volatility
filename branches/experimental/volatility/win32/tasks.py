# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
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

import volatility.obj as obj
import volatility.win32.info as info
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.scan as scan
import volatility.conf as conf
import volatility.addrspace as addrspace
config = conf.ConfObject()
import pdb

def pslist(addr_space):
    """ A Generator for _EPROCESS objects (uses _KPCR symbols) """
    ## First try to find it with the debugger data block entry in a
    ## crash dump address space.
    try:
        KdDebuggerDataBlock = obj.Object("_KDDEBUGGER_DATA64",
                     offset=addr_space.base.header.KdDebuggerDataBlock,
                     vm=addr_space)

        PsActiveProcessHead = KdDebuggerDataBlock.PsActiveProcessHead
    except:
        ## Maybe its not a crash dump? Look for KPCR at a hard coded address:
        kpcra = config.KPCR or info.kpcr_addr
        kpcr = obj.Object("_KPCR",
                          offset=kpcra,
                          vm=addr_space)

        DebuggerDataList = kpcr.KdVersionBlock.dereference_as("_DBGKD_GET_VERSION64").DebuggerDataList
        ## Several options for PsActiveProcessHead from various sources.
        PsActiveProcessHead =  DebuggerDataList.dereference_as(
            "_KDDEBUGGER_DATA64").PsActiveProcessHead or \
            DebuggerDataList.dereference_as(
            "_KDDEBUGGER_DATA32").PsActiveProcessHead or \
            kpcr.KdVersionBlock.dereference_as(
            "_KDDEBUGGER_DATA32").PsActiveProcessHead

    if PsActiveProcessHead:
        # print type(PsActiveProcessHead)
    ## Try to iterate over the process list in PsActiveProcessHead
    ## (its really a pointer to a _LIST_ENTRY)
        for l in PsActiveProcessHead.dereference_as("_LIST_ENTRY").list_of_type(
            "_EPROCESS", "ActiveProcessLinks"):
            yield l
    else:
        raise RuntimeError("Unable to find PsActiveProcessHead - is this image supported?")

# Blocksize was chosen to make it aligned
# on 8 bytes
# Optimized by Michael Cohen

BLOCKSIZE = 1024 * 1024 * 10

def create_addr_space(kaddr_space, directory_table_base):

    try:
        process_address_space = kaddr_space.__class__(kaddr_space.base, directory_table_base)
    except:
        return None

    return process_address_space


