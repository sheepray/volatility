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


# really 'file' but don't want to mess with python's version
class linux_file(obj.CType):

    def get_dentry(self):

        if hasattr(self, "dentry"):
            ret = self.dentry
        else:
            ret = self.f_path.dentry

        return ret

    def get_vfsmnt(self):

        if hasattr(self, "f_vfsmnt"):
            ret = self.f_vfsmnt
        else:
            ret = self.f_path.mnt

        return ret

class files_struct(obj.CType):

    def get_fds(self):

        if hasattr(self, "fdt"):
            fdt = self.fdt
            ret = fdt.fd.dereference()
        else:
            ret = self.fd.dereference()

        return ret

    def max_fds(self):

        if hasattr(self, "fdt"):
            ret = self.fdt.max_fds
        else:
            ret = self.max_fds

        return ret

class task_struct(obj.CType):

    def get_uid(self):

        if hasattr(self, "uid"):
            ret = self.uid
        else:
            ret = self.cred.uid

        return ret

    def get_gid(self):

        if hasattr(self, "gid"):
            ret = self.uid
        else:
            ret = self.cred.gid

        return ret

    def get_euid(self):

        if hasattr(self, "euid"):
            ret = self.uid
        else:
            ret = self.cred.euid

        return ret

AbstractLinuxProfile.object_classes['task_struct'] = task_struct
AbstractLinuxProfile.object_classes['files_struct'] = files_struct
AbstractLinuxProfile.object_classes['file'] = linux_file




