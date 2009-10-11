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


# The source code in this file was inspired by the excellent work of
# Brendan Dolan-Gavitt. Background information can be found in 
# the following reference:
# "The VAD Tree: A Process-Eye View of Physical Memory," Brendan Dolan-Gavitt

#pylint: disable-msg=C0111

vad_flags = { \
'_MMVAD_FLAGS' : { \
  'CommitCharge' : [0x0, 0x13], \
  'PhysicalMapping' : [0x13, 0x1], \
  'ImageMap' : [0x14, 0x1], \
  'UserPhysicalPages' : [0x15, 0x1], \
  'NoChange' : [0x16, 0x1], \
  'WriteWatch' : [0x17, 0x1], \
  'Protection' : [0x18, 0x5], \
  'LargePages' : [0x1D, 0x1], \
  'MemCommit' : [0x1E, 0x1], \
  'PrivateMemory' : [0x1F, 0x1], \
},
'_MMVAD_FLAGS2' : { \
  'FileOffset' : [0x0, 0x18], \
  'SecNoChange' : [0x18, 0x1], \
  'OneSecured' : [0x19, 0x1], \
  'MultipleSecured' : [0x1a, 0x1], \
  'ReadOnly' : [0x1b, 0x1], \
  'LongVad' : [0x1c, 0x1], \
  'ExtendableFile' : [0x1d, 0x1], \
  'Inherit' : [0x1e, 0x1], \
  'CopyOnWrite' : [0x1f, 0x1], \
},
'_MMSECTION_FLAGS' : { \
   'BeingDeleted' : [0x0, 0x1], \
   'BeingCreated' : [0x1, 0x1], \
   'BeingPurged'  : [0x2, 0x1], \
   'NoModifiedWriting' : [ 0x3, 0x1], \
   'FailAllIo' : [0x4, 0x1], \
   'Image' : [0x5, 0x1], \
   'Based' : [0x6, 0x1], \
   'File'  : [0x7, 0x1], \
   'Networked' : [0x8, 0x1], \
   'NoCache' : [0x9, 0x1], \
   'PhysicalMemory' : [0xa, 0x1], \
   'CopyOnWrite' : [0xb, 0x1], \
   'Reserve' : [0xc, 0x1], \
   'Commit' : [0xd, 0x1], \
   'FloppyMedia' : [0xe, 0x1], \
   'WasPurged' : [0xf, 0x1], \
   'UserReference' : [0x10, 0x1], \
   'GlobalMemory' : [0x11, 0x1], \
   'DeleteOnClose' : [0x12, 0x1], \
   'FilePointerNull' : [0x13, 0x1], \
   'DebugSymbolsLoaded' : [0x14, 0x1], \
   'SetMappedFileIoComplete' : [0x15, 0x1], \
   'CollidedFlush' : [0x16, 0x1], \
   'NoChange' : [0x17, 0x1], \
   'HadUserReference' : [0x18, 0x1], \
   'ImageMappedInSystemSpace' : [0x19, 0x1], \
   'UserWritable' : [0x1a, 0x1], \
   'Accessed' : [0x1b, 0x1], \
   'GlobalOnlyPerSession' : [0x1c, 0x1], \
   'Rom' : [0x1d, 0x1], \
   'filler' : [0x1e, 0x2], \
}
}

def get_mask_flag(flags, member):
    if not vad_flags.has_key(flags):
        raise Exception('Invalid flags ' + flags)
    flag_dict = vad_flags[flags]
    v = flag_dict[member]
    bits = 2**v[1] - 1
    mask = bits << v[0]
    return mask

def get_bit_flags(value, flags):
    matches = []
    if not vad_flags.has_key(flags):
        raise Exception('Invalid flags ' + flags)
    bit_dict = vad_flags[flags] 
    for (k, v) in bit_dict.items():
        if ((v[1] == 0x1) and ((( 1 << (v[0])) & value) > 0)):
            matches.append(k)
    return matches