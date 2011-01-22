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

#pylint: disable-msg=C0111

import volatility.commands as commands
import volatility.win32 as win32
import volatility.utils as utils

class Modules(commands.command):
    """Print list of loaded modules"""
    def render_text(self, outfd, data):
        header = False

        for module in data:
            if not header:
                outfd.write("{0:50} {1:12} {2:8} {3}\n".format('File', 'Base', 'Size', 'Name'))
                header = True
            outfd.write("{0:50} 0x{1:010x} 0x{2:06x} {3}\n".format(module.FullDllName, module.DllBase, module.SizeOfImage, module.BaseDllName))

    def calculate(self):
        addr_space = utils.load_as(self._config)

        result = win32.modules.lsmod(addr_space)

        return result
