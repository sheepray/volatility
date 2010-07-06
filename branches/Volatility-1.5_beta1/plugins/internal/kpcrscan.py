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

import volatility.utils as utils
import volatility.commands as commands
import volatility.conf as conf
import volatility.obj as obj
import volatility.scan as scan
import struct

config = conf.ConfObject()
class KPCRScannerCheck(scan.ScannerCheck):
    def __init__(self, address_space):
        scan.ScannerCheck.__init__(self, address_space)
        self.vm = address_space
        kpcr = obj.Object("_KPCR", vm=self.vm, offset=0)
        self.SelfPcr_offset = kpcr.SelfPcr.offset
        self.Prcb_offset = kpcr.Prcb.offset
        self.PrcbData_offset = kpcr.PrcbData.offset
        self.KPCR = None

    def check(self, offset):
        """ We check that _KCPR.pSelfPCR points to the start of the _KCPR struct """
        paKCPR = offset
        paPRCBDATA = offset + self.PrcbData_offset

        try:
            pSelfPCR = obj.Object('unsigned long', offset=(offset + self.SelfPcr_offset), vm=self.vm)
            pPrcb = obj.Object('unsigned long', offset=(offset + self.Prcb_offset), vm=self.vm)
            if (pSelfPCR == paKCPR and pPrcb == paPRCBDATA):
                self.KPCR = pSelfPCR
                return True

        except Exception:
            return False

        return False

    # make the scan DWROD aligned
    def skip(self, data, offset):
        offset_string = struct.pack("I", offset)

        new_offset = offset
        ## A successful match will need to at least match the Most
        ## Significant 3 bytes
        while (new_offset + self.SelfPcr_offset) & 0xFF >= self.SelfPcr_offset:
            new_offset = data.find(offset_string[3], new_offset + 1)
            ## Its not there, skip the whole buffer
            if new_offset < 0:
                return len(data) - offset

            if (new_offset % 4) == 0:
                return new_offset - self.SelfPcr_offset - 1

        return len(data)-offset

class KPCRScanner(scan.DiscontigScanner):
    checks = [ ("KPCRScannerCheck", {})
               ]
    def scan(self, address_space, offset=0, maxlen=None):
        return scan.DiscontigScanner.scan(self, address_space, max(offset, 0x80000000), maxlen)
                        
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

