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
import volatility.obj as obj
import volatility.scan as scan
import pdb
import struct

config = conf.ConfObject()
class KPCRScannerCheck(scan.ScannerCheck):
    def __init__(self, address_space):
        scan.ScannerCheck.__init__(self, address_space)
        kpcr = obj.Object("_KPCR", vm=address_space, offset=0)
        self.SelfPcr_offset = kpcr.SelfPcr.offset
        self.Prcb_offset = kpcr.Prcb.offset
        self.PrcbData_offset = kpcr.PrcbData.offset

    def check(self, offset):
        """ We check that _KCPR.pSelfPCR points to the start of the _KCPR struct """
        paKCPR = offset
        paPRCBDATA = offset + self.PrcbData_offset

        try:
            pSelfPCR = struct.unpack("I", self.address_space.read(offset + self.SelfPcr_offset,4))[0]
            pPrcb = struct.unpack("I", self.address_space.read(offset + self.Prcb_offset,4))[0]
            if (pSelfPCR == paKCPR and pPrcb ==  paPRCBDATA):
                self.KPCR = pSelfPCR
                return True

        except Exception,e:
            return False

        return False

    # make the scan DWROD aligned
    def skip(self, data, offset, base_offset):
        print hex(offset + base_offset)
        offset_string = struct.pack("I", offset + base_offset)

        if offset + base_offset >= 0x81c00000L: pdb.set_trace()
        if '81cec700' in offset_string: pdb.set_trace()

        #pdb.set_trace()
        new_offset = offset
        ## A successful match will need to at least match the Most
        ## Significant 3 bytes
        while (new_offset + base_offset + self.SelfPcr_offset) & 0xFF >= self.SelfPcr_offset:
            new_offset = data.find(offset_string[3], new_offset + 1)
            ## Its not there, skip the whole buffer
            if new_offset < 0:
                return len(data) - offset

            if ((new_offset + base_offset) % 4) == 0:
                return new_offset - self.SelfPcr_offset - 1

        return len(data)-offset

class KPCRScanner(scan.DiscontigScanner):
    checks = [ ("KPCRScannerCheck", {})
               ]
    def scan(self, address_space):
        
        for (offset,length) in self.getAvailableRuns(address_space):
            # only test for KPCR structure in the upper half of the 4G x86 address space (ie Kernel space)
            if (offset >= 0x80000000):
                for match in scan.BaseScanner.scan(self,address_space, offset, length):
                    yield match
                        
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

        #result = kpcr.KPCRScan(addr_space).scan()
        result = []
        sc = KPCRScanner()
        print "Scanning for KPCR..."
        for o in sc.scan(addr_space):
            print "\tFound KPCR stucture at %x" % o
            result.append(o)
        if len(result) == 0:
            config.error("No KPCR structures found. (Is it a windows image?)")

        return result

    def render_text(self, outfd, data):
        """Renders the KPCR values as text"""

        outfd.write("Potential KPCR structure virtual addresses:\n")
        for o in data:
            outfd.write(" _KPCR: %x\n" % o)

config.add_option("KPCR", type='int', default=0, help = "KPCR Address")  

