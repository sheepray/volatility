# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

import volatility.plugins.taskmods as taskmods

class RegObjKeys(taskmods.Files):
    """Print list of open regkeys for each process"""

    def __init__(self, config, *args):
        taskmods.Files.__init__(self, config, *args)
        self.handle_type = 'Key'
        self.handle_obj = '_CM_KEY_BODY'

    def render_text(self, outfd, data):
        first = True
        offsettype = "(V)" if not self._config.PHYSICAL_OFFSET else "(P)"
        for pid, handles in data:
            if not first:
                outfd.write("*" * 72 + "\n")
            outfd.write("Offset{0}  Type   Pid: {1:6}\n".format(offsettype, pid))
            first = False

            for h in handles:
                if not self._config.PHYSICAL_OFFSET:
                    offset = h.obj_offset
                else:
                    offset = h.obj_vm.vtop(h.obj_offset)
                keyname = self.full_key_name(h)
                outfd.write("{0:#010x} {1:6} {2:40}\n".format(offset, "Key", keyname))

    def full_key_name(self, handle):
        """Returns the full name of a registry key based on its CM_KEY_BODY handle"""
        output = []
        kcb = handle.KeyControlBlock
        while kcb.ParentKcb:
            if kcb.NameBlock.Name != None:
                output.append(str(kcb.NameBlock.Name))
            kcb = kcb.ParentKcb
        return "\\".join(reversed(output))

