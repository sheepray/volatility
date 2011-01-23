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

import volatility.commands as commands
import volatility.utils    as utils
import volatility.obj      as obj

def mask_number(num):
    return num & 0xffffffff

class AbstractLinuxCommand(commands.command):

    def __init__(self, *args, **kwargs):
        commands.command.__init__(*args, **kwargs)
        self.addr_space = utils.load_as(self._config)
        self.profile = self.addr_space.profile
        vmagic = obj.Object('VOLATILITY_MAGIC', vm = self.addr_space, offset = 0x00)
        self.smap = vmagic.system_map.v()

def sizeofstruct(struct_name, profile):

    return profile.typeDict[struct_name][0]

def offsetof(struct_name, list_member, profile):

    offset = profile.typeDict[struct_name][1][list_member][0]
    return offset

# similar to for_each_process for this usage
def walk_list_head(struct_name, list_member, list_head_ptr, addr_space):

    list_ptr = list_head_ptr.next

    while 1:

        # return the address of the beginning of the strucutre, similar to list.h in kernel
        yield obj.Object(struct_name, offset = list_ptr - offsetof(struct_name, list_member, addr_space.profile), vm = addr_space)

        list_ptr = obj.Object("list_head", vm = addr_space, offset = list_ptr)

        list_ptr = list_ptr.next

        if list_ptr == list_head_ptr:
            break

def walk_internal_list(struct_name, list_member, list_start, addr_space):

    # mm->mmap

    member_off = offsetof(struct_name, list_member, addr_space.profile)

    while 1:

        list_struct = obj.Object(struct_name, vm = addr_space, offset = list_start)

        yield list_struct

        list_start = list_struct.__getattribute__(list_member)

        if not list_start:
            break

def get_string(addr, addr_space, maxlen = 256):

    name = addr_space.read(addr, maxlen)
    ret = ""

    for n in name:
        if ord(n) == 0:
            break
        ret = ret + n

    return ret


def format_path(path_list):

    path = '/'.join(path_list)

    return path

def IS_ROOT(dentry):

    return dentry == dentry.d_parent

# based on __d_path
# TODO: (deleted) support
def get_path(task, filp, addr_space):

    root = task.fs.root
    dentry = filp.f_path.dentry
    inode = dentry.d_inode
    vfsmnt = filp.f_path.mnt
    ret_path = []

    while 1:

        dname = get_string(dentry.d_name.name, addr_space)

        if dname != '/':
            ret_path.append(dname)

        if dentry == root.dentry and vfsmnt == root.mnt:
            break

        if dentry == vfsmnt.mnt_root or IS_ROOT(dentry):
            if vfsmnt.mnt_parent == vfsmnt:
                break
            dentry = vfsmnt.mnt_mountpoint
            vfsmnt = vfsmnt.mnt_parent
            continue

        parent = dentry.d_parent

        dentry = parent

    ret_path.reverse()

    ret_val = format_path(ret_path)

    if ret_val.startswith(("socket:", "pipe:")):
        ret_val = ret_val[:-1] + "[{0}]".format(inode.i_ino)
    else:
        ret_val = '/' + ret_val

    return ret_val

# returns the dentry and inode of a file
def file_info(filp, addr_space):

    fobj = obj.Object("file", offset = filp, vm = addr_space)
    dentry = obj.Object("dentry", offset = fobj.f_path.dentry, vm = addr_space)
    inode = obj.Object("inode", offset = dentry.d_inode, vm = addr_space)

    return (dentry, inode)
