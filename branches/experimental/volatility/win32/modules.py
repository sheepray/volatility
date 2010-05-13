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
import volatility.conf as conf
config = conf.ConfObject()

def lsmod(addr_space):
    """ A Generator for modules (uses _KPCR symbols) """
    ## Locate the kpcr struct - either hard coded or specified by the command line
    kpcra = None
    if config.KPCR == 0:
        kpcra = info.kpcr_addr
    else:
        kpcra = config.KPCR
        
    kpcr = obj.Object("_KPCR",
                     offset=kpcra,
                     vm=addr_space)

    ## Try to dereference the KdVersionBlock as a 64 bit struct
    DebuggerDataList = kpcr.KdVersionBlock.dereference_as("_DBGKD_GET_VERSION64").DebuggerDataList

    PsLoadedModuleList = DebuggerDataList.dereference_as("_KDDEBUGGER_DATA64"
                                                          ).PsLoadedModuleList \
                     or DebuggerDataList.dereference_as("_KDDEBUGGER_DATA32"
                                                        ).PsLoadedModuleList \
                     or kpcr.KdVersionBlock.dereference_as("_KDDEBUGGER_DATA32"
                                                           ).PsLoadedModuleList
    if PsLoadedModuleList.is_valid():
        offset = PsLoadedModuleList.dereference().v()
        ## This is a pointer to a _KDDEBUGGER_DATA64 struct. We only
        ## care about the PsActiveProcessHead entry:


        ## Try to iterate over the process list in PsActiveProcessHead
        ## (its really a pointer to a _LIST_ENTRY)
        for l in PsLoadedModuleList.dereference_as("_LIST_ENTRY").list_of_type(
            "_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"):
            yield l