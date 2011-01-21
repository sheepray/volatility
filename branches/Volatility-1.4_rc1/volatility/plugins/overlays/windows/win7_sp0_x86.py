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
import win7_sp0_x86_vtypes
import vista_sp0_x86
import windows
import crash_vtypes
import hibernate_vtypes
import tcpip_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611

win7sp0x86overlays = copy.deepcopy(vista_sp0_x86.vistasp0x86overlays)

win7sp0x86overlays['VOLATILITY_MAGIC'][1]['DTBSignature'][1] = ['VolatilityMagic', dict(value = "\x03\x00\x26\x00")]
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['KPCR'][1] = ['VolatilityKPCR', dict(configname = 'KPCR')]
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['KDBGHeader'][1] = ['VolatilityMagic', dict(value = '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x40\x03')]
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['HiveListOffset'][1] = ['VolatilityMagic', dict(value = 0x30c)]
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['HiveListPoolSize'][1] = ['VolatilityMagic', dict(value = 0x638)]

# Add a new member to the VOLATILIY_MAGIC type
win7sp0x86overlays['VOLATILITY_MAGIC'][1]['ObjectPreamble'] = [ 0x0, ['VolatilityMagic', dict(value = '_OBJECT_HEADER_CREATOR_INFO')]]

win7_sp0_x86_vtypes.ntkrpamp_types.update(crash_vtypes.crash_vtypes)
win7_sp0_x86_vtypes.ntkrpamp_types.update(hibernate_vtypes.hibernate_vtypes)
win7_sp0_x86_vtypes.ntkrpamp_types.update(tcpip_vtypes.tcpip_vtypes)

class Win7SP0x86(windows.AbstractWindows):
    """ A Profile for Windows 7 SP0 x86 """
    abstract_types = win7_sp0_x86_vtypes.ntkrpamp_types
    overlay = win7sp0x86overlays
    object_classes = copy.deepcopy(vista_sp0_x86.VistaSP0x86.object_classes)
