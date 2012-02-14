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

import volatility.obj as obj

class Windows64Hook(obj.Hook):

    def check(self, profile):
        return (profile.metadata.get('memory_model', '32bit') == '64bit' and
                profile.metadata.get('os', None) == 'windows')

    def modify_vtypes(self, profile):
        profile.merge_overlay({'VOLATILITY_MAGIC': [ 0x0, {
                                    'PoolAlignment': [ 0x0, ['VolatilityMagic', dict(value = 16)] ]
                                                           }
                                                    ]})

    def modify_overlay(self, profile):
        # This is the location of the MMVAD type which controls how to parse the
        # node. It is located before the structure.
        profile.merge_overlay({'_MMVAD_SHORT': [None, {
                                    'Tag' : [-12, None],
                                  }],
                               '_MMVAD_LONG' : [None, {
                                    'Tag' : [-12, None],
                                                       }]
                               })

    def modify_object_classes(self, profile):
        profile.object_classes.update({'Pointer64': obj.Pointer})
