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
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.utils as utils

class TasksNotFound(utils.VolatilityException):
    """Thrown when a tasklist cannot be determined"""
    pass

def pslist(addr_space):
    """ A Generator for _EPROCESS objects (uses _KPCR symbols) """

    volmagic = obj.Object('VOLATILITY_MAGIC', 0x0, addr_space)
    kpcra = volmagic.KPCR.v()

    kpcrval = obj.Object("_KPCR", offset = kpcra, vm = addr_space)

    DebuggerDataList = kpcrval.KdVersionBlock.dereference_as("_DBGKD_GET_VERSION64").DebuggerDataList
    PsActiveProcessHead = DebuggerDataList.dereference_as("_KDDEBUGGER_DATA64"
                                                          ).PsActiveProcessHead \
                     or DebuggerDataList.dereference_as("_KDDEBUGGER_DATA32"
                                                        ).PsActiveProcessHead \
                     or kpcrval.KdVersionBlock.dereference_as("_KDDEBUGGER_DATA32"
                                                           ).PsActiveProcessHead

    if PsActiveProcessHead:
        # Try to iterate over the process list in PsActiveProcessHead
        # (its really a pointer to a _LIST_ENTRY)
        for l in PsActiveProcessHead.dereference_as("_LIST_ENTRY").list_of_type("_EPROCESS", "ActiveProcessLinks"):
            yield l
    else:
        raise TasksNotFound("Could not list tasks, please verify the --profile option and whether this image is valid")
