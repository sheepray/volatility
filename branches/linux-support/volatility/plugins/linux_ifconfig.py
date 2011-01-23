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

class linux_ifconfig(linux_common.AbstractLinuxCommand):

    ''' gathers active interfaces '''

    def calculate(self):

        inet6_ifaddr = self.smap["inet6_addr_lst"] #obj.Object('Pointer', offset=self.smap["inet6_addr_lst"], vm=self.addr_space)

        ifs = obj.Object(theType = 'Array', offset = inet6_ifaddr, vm = self.addr_space, targetType = 'Pointer', count = 16)

        for i in xrange(0, 16):
            iface = ifs[i]

            if iface:
                iface = obj.Object("inet6_ifaddr", offset = iface, vm = self.addr_space)
                yield iface

    def render_text(self, outfd, data):

        for iface in data:
            outfd.write("iface: {0:s}\n".format(iface.idev.dev.name))
