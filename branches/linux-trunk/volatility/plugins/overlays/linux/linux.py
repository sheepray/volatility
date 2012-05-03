# Volatility
# Copyright (C) 2010 Brendan Dolan-Gavitt
# Copyright (c) 2011 Michael Cohen <scudette@gmail.com>
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
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      brendandg@gatech.edu
@organization: Georgia Institute of Technology
"""

import os
import zipfile

import volatility.plugins
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils


linux_overlay = {
    'task_struct' : [None, {
        'comm'          : [ None , ['String', dict(length = 16)]],
        }],
    'module'      : [None, {
        'name'          : [ None , ['String', dict(length = 60)]],
        }],
    'super_block' : [None, {
        's_id'          : [ None , ['String', dict(length = 32)]],
        }],
    'net_device'  : [None, {
        'name'          : [ None , ['String', dict(length = 16)]],
        }],
    'sockaddr_un' : [None, {
        'sun_path'      : [ None , ['String', dict(length = 108)]],
        }],
    'cpuinfo_x86' : [None, {
        'x86_model_id'  : [ None , ['String', dict(length = 64)]],
        'x86_vendor_id' : [ None, ['String', dict(length = 16)]],
        }],
    }

def parse_system_map(data):
    """Parse the symbol file."""
    sys_map = {}
    # get the system map
    for line in data.splitlines():
        (address, _, symbol) = line.strip().split()
        try:
            sys_map[symbol] = long(address, 16)
        except ValueError:
            pass

    return sys_map

def LinuxProfileFactory(profpkg):
    """Takes in a zip file, spits out a LinuxProfile class"""

    vtypesvar = {}
    sysmapvar = {}

    profilename = os.path.splitext(os.path.basename(profpkg.filename))[0]
    profilename = 'Linux' + profilename.replace('.', '_')

    for f in profpkg.filelist:
        if f.filename.lower().endswith('.dwarf'):
            data = profpkg.read(f.filename)
            vtypesvar.update(utils.DWARFParser(data).finalize())
            debug.info("{2}: Found dwarf file {0} with {1} symbols".format(f.filename, len(vtypesvar.keys()), profilename))
        elif 'system.map' in f.filename.lower():
            sysmapvar.update(parse_system_map(profpkg.read(f.filename)))
            debug.info("{2}: Found system file {0} with {1} symbols".format(f.filename, len(sysmapvar.keys()), profilename))

    if not sysmapvar or not vtypesvar:
        # Might be worth throwing an exception here?
        return None

    class AbstractLinuxProfile(obj.Profile):
        """A Linux profile which works with dwarfdump output files.
    
        To generate a suitable dwarf file:
        dwarfdump -di vmlinux > output.dwarf
        """
        _md_os = "linux"
        _md_memory_model = "32bit"

        def __init__(self, *args, **kwargs):
            self.sysmap = {}
            obj.Profile.__init__(self, *args, **kwargs)

        def load_vtypes(self):
            """Loads up the vtypes data"""
            self.vtypes.update(vtypesvar)

        def load_sysmap(self):
            """Loads up the system map data"""
            self.sysmap.update(sysmapvar)

    cls = AbstractLinuxProfile
    cls.__name__ = profilename
    return cls

################################
# Track down the zip files
# Push them through the factory
# Check whether ProfileModifications will work

new_classes = []

for path in set(volatility.plugins.__path__):
    for path, _, files in os.walk(path):
        for fn in files:
            if zipfile.is_zipfile(os.path.join(path, fn)):
                new_classes.append(LinuxProfileFactory(zipfile.ZipFile(os.path.join(path, fn))))

################################

# really 'file' but don't want to mess with python's version
class linux_file(obj.CType):

    def get_dentry(self):
        if hasattr(self, "f_dentry"):
            ret = self.f_dentry
        else:
            ret = self.f_path.dentry

        return ret

    def get_vfsmnt(self):
        if hasattr(self, "f_vfsmnt"):
            ret = self.f_vfsmnt
        else:
            ret = self.f_path.mnt

        return ret

class list_head(obj.CType):
    """A list_head makes a doubly linked list."""
    def list_of_type(self, type, member, forward = True):
        if not self.is_valid():
            return

        ## Get the first element
        if forward:
            lst = self.next.dereference()
        else:
            lst = self.prev.dereference()

        offset = self.obj_vm.profile.get_obj_offset(type, member)

        seen = set()
        seen.add(lst.obj_offset)

        while 1:
            ## Instantiate the object
            item = obj.Object(type, offset = lst.obj_offset - offset,
                                    vm = self.obj_vm,
                                    parent = self.obj_parent,
                                    name = type)


            if forward:
                lst = item.m(member).next.dereference()
            else:
                lst = item.m(member).prev.dereference()

            if not lst.is_valid() or lst.obj_offset in seen:
                return
            seen.add(lst.obj_offset)

            yield item

    def __nonzero__(self):
        ## List entries are valid when both Flinks and Blink are valid
        return bool(self.next) or bool(self.prev)

    def __iter__(self):
        return self.list_of_type(self.obj_parent.obj_name, self.obj_name)

class files_struct(obj.CType):

    def get_fds(self):
        if hasattr(self, "fdt"):
            fdt = self.fdt
            ret = fdt.fd.dereference()
        else:
            ret = self.fd.dereference()

        return ret

    def get_max_fds(self):
        if hasattr(self, "fdt"):
            ret = self.fdt.max_fds
        else:
            ret = self.max_fds

        return ret

class task_struct(obj.CType):

    @property
    def uid(self):
        ret = self.members.get("uid")
        if ret is None:
            ret = self.cred.uid

        return ret

    @property
    def gid(self):
        ret = self.members.get("gid")
        if ret is None:
            ret = self.cred.gid

        return ret

    @property
    def euid(self):
        ret = self.members.get("euid")
        if ret is None:
            ret = self.cred.euid

        return ret

    def get_process_address_space(self):
        directory_table_base = self.obj_vm.vtop(self.mm.pgd.v())

        try:
            process_as = self.obj_vm.__class__(
                self.obj_vm.base, self.obj_vm.get_config(), dtb = directory_table_base)

        except AssertionError, _e:
            return obj.NoneObject("Unable to get process AS")

        process_as.name = "Process {0}".format(self.pid)

        return process_as

class linux_fs_struct(obj.CType):

    def get_root_dentry(self):
        # < 2.6.26
        if hasattr(self, "rootmnt"):
            ret = self.root
        else:
            ret = self.root.dentry

        return ret

    def get_root_mnt(self):
        # < 2.6.26
        if hasattr(self, "rootmnt"):
            ret = self.rootmnt
        else:
            ret = self.root.mnt

        return ret

class VolatilityDTB(obj.VolatilityMagic):
    """A scanner for DTB values."""

    def generate_suggestions(self):
        """Tries to locate the DTB."""
        volmag = obj.Object('VOLATILITY_MAGIC', offset = 0, vm = self.obj_vm)

        # This is the difference between the virtual and physical addresses (aka
        # PAGE_OFFSET). On linux there is a direct mapping between physical and
        # virtual addressing in kernel mode:

        #define __va(x) ((void *)((unsigned long) (x) + PAGE_OFFSET))
        PAGE_OFFSET = volmag.SystemMap["_text"] - volmag.SystemMap["phys_startup_32"]

        yield volmag.SystemMap["swapper_pg_dir"] - PAGE_OFFSET

class LinuxObjectClasses(obj.ProfileModification):
    conditions = {'os': lambda x: x == 'windows'}
    before = ['BasicObjectClasses']

    def modification(self, profile):
        profile.object_classes.update({
            'fs_struct': linux_fs_struct,
            'file': linux_file,
            'list_head': list_head,
            'files_struct': files_struct,
            'task_struct': task_struct,
            'VolatilityDTB': VolatilityDTB,
            })
