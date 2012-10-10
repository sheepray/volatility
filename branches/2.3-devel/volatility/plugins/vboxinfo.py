# Volatility
# Copyright (C) 2009-2012 Volatile Systems
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

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.debug as debug

class VBoxInfo(common.AbstractWindowsCommand):
    """Dump virtualbox information"""
    
    def calculate(self):
        addr_space = utils.load_as(self._config)
                
        result = None
        adrs = addr_space
        while adrs:
            if adrs.__class__.__name__ == 'VirtualBoxCoreDumpElf64':
                result = adrs
            adrs = adrs.base
            
        if result is None:
            debug.error("Memory image could not be identified as a virtualbox core dump")
            
        return result
        
    def render_text(self, outfd, data):
    
        core_desc = data.get_core_desc()
        
        outfd.write("Magic: {0:#x}\n".format(core_desc.u32Magic))
        outfd.write("Format: {0:#x}\n".format(core_desc.u32FmtVersion))
        outfd.write("VirtualBox {0}.{1}.{2} (revision {3})\n".format(
                core_desc.Major, 
                core_desc.Minor, core_desc.Build, 
                core_desc.u32VBoxRevision))
        outfd.write("CPUs: {0}\n\n".format(core_desc.cCpus))
        
        self.table_header(outfd, [("File Offset", "[addrpad]"), 
                                  ("Memory Offset", "[addrpad]"), 
                                  ("Size", "[addrpad]")])
        
        for memory_offset, file_offset, length in data.get_runs():
            self.table_row(outfd, file_offset, memory_offset, length)
