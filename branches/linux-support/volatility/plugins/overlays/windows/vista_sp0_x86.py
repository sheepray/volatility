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
import vista_sp0_x86_vtypes
import vista_sp0_x86_syscalls
import xp_sp2_x86
import windows
import tcpip_vtypes
import crash_vtypes
import hibernate_vtypes
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.obj as obj

vistasp0x86overlays = copy.deepcopy(xp_sp2_x86.xpsp2overlays)

vistasp0x86overlays['_MMVAD_SHORT'][1]['Flags'][0] = lambda x: x.u.obj_offset
vistasp0x86overlays['_CONTROL_AREA'][1]['Flags'][0] = lambda x: x.u.obj_offset
vistasp0x86overlays['_MMVAD_LONG'][1]['Flags'][0] = lambda x: x.u.obj_offset
vistasp0x86overlays['_MMVAD_LONG'][1]['Flags2'][0] = lambda x: x.u2.obj_offset

vistasp0x86overlays['_EPROCESS'][1]['VadRoot'][1] = ['_MM_AVL_TABLE']

vistasp0x86overlays['VOLATILITY_MAGIC'][1]['DTBSignature'][1] = ['VolatilityMagic', dict(value = "\x03\x00\x20\x00")]
vistasp0x86overlays['VOLATILITY_MAGIC'][1]['KPCR'][1] = ['VolatilityKPCR', dict(configname = 'KPCR')]
vistasp0x86overlays['VOLATILITY_MAGIC'][1]['KDBGHeader'][1] = ['VolatilityMagic', dict(value = '\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x28\x03')]
vistasp0x86overlays['VOLATILITY_MAGIC'][1]['HiveListOffset'][1] = ['VolatilityMagic', dict(value = 0x308)]
vistasp0x86overlays['VOLATILITY_MAGIC'][1]['HiveListPoolSize'][1] = ['VolatilityMagic', dict(value = 0x5d8)]

vista_sp0_x86_vtypes.ntkrnlmp_types.update(crash_vtypes.crash_vtypes)
vista_sp0_x86_vtypes.ntkrnlmp_types.update(hibernate_vtypes.hibernate_vtypes)
vista_sp0_x86_vtypes.ntkrnlmp_types.update(tcpip_vtypes.tcpip_vtypes)

class VistaSP0x86(windows.AbstractWindows):
    """ A Profile for Windows Vista SP0 x86 """
    abstract_types = vista_sp0_x86_vtypes.ntkrnlmp_types
    overlay = vistasp0x86overlays
    object_classes = windows.AbstractWindows.object_classes.copy()
    syscalls = vista_sp0_x86_syscalls.syscalls

class _MM_AVL_TABLE(obj.CType):
    def traverse(self):
        """
        This is a hack to get around the fact that _MM_AVL_TABLE.BalancedRoot (an _MMADDRESS_NODE) doesn't
        work the same way as the other _MMADDRESS_NODEs. In particular, we want _MMADDRESS_NODE to behave
        like _MMVAD, and all other _MMADDRESS_NODEs have a Vad, VadS, Vadl tag etc, but _MM_AVL_TABLE.BalancedRoot
        does not. So we can't reference self.BalancedRoot.RightChild here because self.BalancedRoot will be None
        due to the fact that there is not a valid VAD tag at self.BalancedRoot.obj_offset - 4 (as _MMVAD expects).

        We want to start traversing from self.BalancedRoot.RightChild. The self.BalancedRoot.LeftChild member
        will always be 0. However, we can't call get_obj_offset("_MMADDRESS_NODE", "RightChild") or it will 
        result in a TypeError: __new__() takes exactly 5 non-keyword arguments (4 given). Therefore, we hard-code
        the offset to the RightChild and treat it as a pointer to the first real _MMADDRESS_NODE. 
        """
        right_child_offset = 8 # self.obj_vm.profile.get_obj_offset("_MMADDRESS_NODE", "RightChild")

        rc = obj.Object("Pointer", vm = self.obj_vm, offset = self.obj_offset + right_child_offset)

        node = obj.Object('_MMADDRESS_NODE', vm = self.obj_vm, offset = rc.v(), parent = self.obj_parent)

        for c in node.traverse():
            yield c

class _EX_FAST_REF(obj.CType):
    def dereference_as(self, theType):
        """Use the _EX_FAST_REF.Object pointer to resolve an object of the specified type"""
        return obj.Object(theType, vm = self.obj_vm, parent = self, offset = self.Object.v() & 0xFFFFFFFC)

class _MMVAD_SHORT(xp_sp2_x86._MMVAD_SHORT):
    def get_parent(self):
        return self.u1.Parent

    def get_control_area(self):
        return self.Subsection.ControlArea

    def get_file_object(self):
        """The FilePointer on Windows 7 is _EX_FAST_REF"""
        return self.Subsection.ControlArea.FilePointer.dereference_as("_FILE_OBJECT")

class _MMVAD_LONG(_MMVAD_SHORT):
    pass

VistaSP0x86.object_classes['_MM_AVL_TABLE'] = _MM_AVL_TABLE
VistaSP0x86.object_classes['_EX_FAST_REF'] = _EX_FAST_REF

VistaSP0x86.object_classes['_MMADDRESS_NODE'] = xp_sp2_x86._MMVAD
VistaSP0x86.object_classes['_MMVAD_SHORT'] = _MMVAD_SHORT
VistaSP0x86.object_classes['_MMVAD_LONG'] = _MMVAD_LONG
