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
        commands.command.__init__(self, *args, **kwargs)
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

    # this happens in rare instances where list_heads get pre-initlized
    # the caller needs to check for not return value
    # currently only needed by linux_mount when walking mount_hashtable
    if list_ptr == list_head_ptr:
        return

    while 1:

        # return the address of the beginning of the strucutre, similar to list.h in kernel
        yield obj.Object(struct_name, offset = list_ptr - offsetof(struct_name, list_member, addr_space.profile), vm = addr_space)

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
def do_get_path(root, dentry, vfsmnt, addr_space):

    ret_path = []

    inode = dentry.d_inode

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

    elif ret_val != "inotify":
        ret_val = '/' + ret_val

    return ret_val

def get_path(task, filp, addr_space):

    root = task.fs.root
    dentry = filp.get_dentry()
    vfsmnt = filp.get_vfsmnt()

    return do_get_path(root, dentry, vfsmnt, addr_space)

# this is here b/c python is retarded and its inet_ntoa can't handle integers...
def ip2str(ip):

    a = ip & 0xff
    b = (ip >> 8) & 0xff
    c = (ip >> 16) & 0xff
    d = (ip >> 24) & 0xff

    return "%d.%d.%d.%d" % (a, b, c, d)


