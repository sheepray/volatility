# Volatility
# Copyright (c) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
@author:       Bradley L Schatz
@license:      GNU General Public License 2.0 or later
@contact:      bradley@schatzforensic.com.au

This file provides support for windows XP SP3. We provide a profile
for SP3.
"""

#pylint: disable-msg=C0111


import xp_sp3_x86_vtypes
import vtypes
import xp_sp2
import crashdump
import hibernate_vtypes
import copy
import volatility.debug as debug #pylint: disable-msg=W0611

from xp_sp2 import WinXPSP2

xpsp3overlays = copy.deepcopy(vtypes.xpsp2overlays)

xpsp3overlays['_MMVAD_SHORT'][1]['Flags'][0] = lambda x: x['u'][0]
xpsp3overlays['_CONTROL_AREA'][1]['Flags'][0] = lambda x: x['u'][0]
xpsp3overlays['_MMVAD_LONG'][1]['Flags'][0] = lambda x: x['u'][0]
xpsp3overlays['_MMVAD_LONG'][1]['Flags2'][0] = lambda x: x['u'][0]

xp_sp3_x86_vtypes.ntoskrnl_types.update(crashdump.crash_vtypes)
xp_sp3_x86_vtypes.ntoskrnl_types.update(hibernate_vtypes.hibernate_vtypes)

class WinXPSP3(xp_sp2.WinXPSP2):
    """ A Profile for windows XP SP3 """
    native_types = vtypes.x86_native_types_32bit
    abstract_types = xp_sp3_x86_vtypes.ntoskrnl_types
    overlay = xpsp3overlays
