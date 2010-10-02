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

import copy
import win7_sp0_x86_vtypes as win7_sp0_x86_vtypes
import xp_sp2_x86 as xp_sp2_x86
import windows as windows
import crashdump as crashdump
import hibernate_vtypes as hibernate_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611

win7sp0x86overlays = copy.deepcopy(xp_sp2_x86.xpsp2overlays)

win7sp0x86overlays['_MMVAD_SHORT'][1]['Flags'][0] = lambda x: x['u'][0]
win7sp0x86overlays['_CONTROL_AREA'][1]['Flags'][0] = lambda x: x['u'][0]
win7sp0x86overlays['_MMVAD_LONG'][1]['Flags'][0] = lambda x: x['u'][0]
win7sp0x86overlays['_MMVAD_LONG'][1]['Flags2'][0] = lambda x: x['u'][0]

win7sp0x86overlays['VOLATILITY_MAGIC'][1]['DTBSignature'][1] = ['VolatilityMagic', dict(value = "\x03\x00\x26\x00")]
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['KPCR'][1] = ['VolatilityKPCR']

win7_sp0_x86_vtypes.ntkrpamp_types.update(crashdump.crash_vtypes)
win7_sp0_x86_vtypes.ntkrpamp_types.update(hibernate_vtypes.hibernate_vtypes)

class Win7SP0x86(windows.AbstractWindows):
    """ A Profile for Windows 7 SP0 x86 """
    abstract_types = win7_sp0_x86_vtypes.ntkrpamp_types
    overlay = win7sp0x86overlays
