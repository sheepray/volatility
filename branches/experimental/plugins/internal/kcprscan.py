# Volatility
#
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
@author:       Bradley Schatz 
@license:      GNU General Public License 2.0 or later
@contact:      bradley@schatzforensic.com.au
@organization: Schatz Forensic
"""

import os
import volatility.utils as utils
import volatility.commands as commands
import volatility.conf as conf
import volatility.win32.kpcr as kpcr

config = conf.ConfObject()

class kpcrscan(commands.command):
    """Search for and dump potential KPCR values"""
    
    meta_info = dict(
        author = 'Bradley Schatz',
        copyright = 'Copyright (c) 2010 Bradley Schatz',
        contact = 'bradley@schatzforensic.com.au',
        license = 'GNU General Public License 2.0 or later',
        url = 'http://www.schatzforensic.com.au/',
        os = 'WIN_32_VISTA_SP0',
        version = '1.0',
        )
        
    def calculate(self):
        """Determines the address space"""
        addr_space = utils.load_as()
        
        result = kpcr.KPCRScan(addr_space).scan()
       
        if len(result) == 0:
            config.error("No KPCR structures found. (Is it a windows image?)")
        
        return result
            
    def render_text(self, outfd, data):
        """Renders the KPCR values as text"""
        
        outfd.write("Potential KPCR structure virtual addresses:\n")
        for o in data:
            outfd.write(" _KPCR: %x\n" % o)
            

config.add_option("KPCR", type='int', default=0, help = "KPCR Address")  
      