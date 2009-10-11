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

from forensics.object2 import NewObject
from forensics.win32.info import kpcr_addr
import forensics.debug as debug

def pslist(addr_space):
    """ A Generator for _EPROCESS objects (uses _KPCR symbols) """
    ## Locate the kpcr struct - this is hard coded right now
    kpcr = NewObject("_KPCR",
                     offset=kpcr_addr,
                     vm=addr_space)

    ## Try to dereference the KdVersionBlock as a 64 bit struct
    DebuggerDataList = kpcr.KdVersionBlock.dereference_as("_DBGKD_GET_VERSION64").DebuggerDataList
    PsActiveProcessHead = DebuggerDataList.dereference_as("_KDDEBUGGER_DATA64"
                                                          ).PsActiveProcessHead \
                     or DebuggerDataList.dereference_as("_KDDEBUGGER_DATA32"
                                                        ).PsActiveProcessHead \
                     or kpcr.KdVersionBlock.dereference_as("_KDDEBUGGER_DATA32"
                                                           ).PsActiveProcessHead
    
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