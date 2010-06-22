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
#

"""
@author:       Bradley Schatz 
@license:      GNU General Public License 2.0 or later
@contact:      bradley@schatzforensic.com.au
@organization: Schatz Forensic
"""

import pdb
import volatility.win32.info as info
import volatility.obj as obj
import volatility.conf as conf
config = conf.ConfObject()

#
# Background to the technique used in this file can be found in 
# Damien Aumaitre (2009) "A little journey inside Windows memory", 
#

config.add_option('KPCR', short_option='k', default=None, type='int',
                  help="Specify a specific KPCR address")

def get_kpcrobj(addr_space):
    ## Locate the kpcr struct - either hard coded or specified by the command line
    kpcra = None
    if config.KPCR is None:
        kpcra = info.kpcr_addr
    else:
        kpcra = config.KPCR
        
    return obj.Object("_KPCR",
                      offset=kpcra,
                      vm=addr_space)

class KPCRScan(object):
    def __init__(self, address_space):
        self.address_space = address_space
        self.KPCR = None
    
    
    # return a list of potential KPCR structures found in a discontiguous virtual address space
    # TODO: this is currently really slow. Can we exploit allocation pools, or some other thing
    #       to limit the numner of addresses to scan?
    def scan(self):
        res = []
        runs =  self.address_space.get_available_addresses()
        for (offset, length) in runs:
            # only test for KPCR structure in the upper half of the 4G x86 address space (ie Kernel space)
            if (offset >= 0x80000000):
                # do a dword aligned scan for potential KPCR structures. Don't scan the remainder of
                # an address ranger if a struct wont fit in it
                # TODO: should remove hard coded length and determine size of struct from profile
                print "%x" % offset
                for i in range((length - 0x1f94) / 4):
                    o = offset + (i * 4)
                    if self.is_KPCR(o):
                        res.append(o)
        return res
    
    # return whether the given offset within the virtual address space is potentially a KPCR structure
    # a match satisfies the constraints:
    #     1. The SelfPcr field at offset 0x1c within the structure contains a pointer to the virtual address of the start of the KPCR structure
    #     2. The Prcb field at offset 0x20 within the structure contains a pointer to the start of the _KPRCB structure
    #        embedded within the KPCR structure at offset 0x120
    # TODO: offset math is dependent on absolute values. It would be nice to use the struct definition to calcultate
    #       at runtime so it works with future generated struct definitions
    # TODO: the pointers are currently being read as unsigned int. Would be nice to resolve as a pointer type for
    #       64bit compatibility
    
    def is_KPCR(self, o):
        paKCPR = o
        paPRCBDATA = o + 0x120

        pSelfPCR = obj.Object("unsigned int", vm=self.address_space, offset=o + 0x1c)
        pPrcb = obj.Object("unsigned int", vm=self.address_space, offset=o + 0x20)
        if (pSelfPCR == paKCPR and pPrcb ==  paPRCBDATA):
            self.KPCR = pSelfPCR
            return True
        else:
            self.KPCR = None
            return False