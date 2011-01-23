# Volatility
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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj
import volatility.conf as conf
import volatility.plugins.overlays.basic as basic

config = conf.ConfObject()

def compute_kernel_version(a, b, c):
    return a * 65536 + b * 256 + c

def apply_overlays(overlay):

    overlay.update({'task_struct' : [None, { 'comm' : [ None , ['String', dict(length = 16)]]}]})
    overlay.update({'module'      : [None, { 'name' : [ None , ['String', dict(length = 60)]]}]})
    overlay.update({'super_block' : [None, { 's_id' : [ None , ['String', dict(length = 32)]]}]})
    overlay.update({'net_device'  : [None, { 'name' : [ None , ['String', dict(length = 16)]]}]})

class AbstractLinuxProfile(obj.Profile):

    # setup native_types and overlays, abstract_types set in each profile
    native_types = basic.x86_native_types_32bit
    overlay = {}
    apply_overlays(overlay)

    # add the system map file option
    config.add_option('SYSTEM_MAP', short_option = 's', type = 'string', help = 'Name of System Map File')

class task_struct(obj.CType):

    def get_uid(self):

        if hasattr(self, "uid"):
            ret = self.uid
        else:
            ret = self.cred.uid

        return ret

AbstractLinuxProfile.object_classes['task_struct'] = task_struct
