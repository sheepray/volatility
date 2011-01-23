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
import linux_common

class linux_mount(linux_common.AbstractLinuxCommand):

    ''' gathers mounted fs/devices '''

    def calculate(self):

        sbs_addr = self.smap["super_blocks"]

        super_blocks = obj.Object("list_head", vm = self.addr_space, offset = sbs_addr)

        # walk the modules list
        for super_block in linux_common.walk_list_head("super_block", "s_list", super_blocks, self.addr_space):

            yield super_block

    def render_text(self, outfd, data):

        for sb in data:
            outfd.write("{0:s}\n".format(sb.s_id))
