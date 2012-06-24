# Volatility
#
# Authors:
# attc - atcuno@gmail.com
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

import struct
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611
import volatility.plugins.addrspaces.intel as intel

class ArmAddressSpace(intel.JKIA32PagedMemory):
    order = 8
    cache = False
    pae = False
    paging_address_space = True
    checkname = 'ArmValidAS'

    @staticmethod
    def register_options(config):
        intel.JKIA32PagedMemory.register_options(config)

        config.add_option("RAM", type = 'int', default = 0, help = "Where ram starts")

    def _cache_values(self):
        '''
        buf = self.base.read(self.dtb, 0x1000)
        if buf is None:
            self.cache = False
        else:
            self.pde_cache = struct.unpack('<' + 'I' * 0x400, buf)
    
        '''
        #print "skipping cache"
        pass

    def page_table_present(self, entry):
        if entry:
            return True # TODO FIXME
        return False

    def pde_index(self, vaddr):
        return vaddr >> 20

    def pgdir_offset(self, val):
        return val & 0x3FFF

    def get_pde(self, vaddr):

        #if self.cache:
        #   return self.pde_cache[self.pde_index(vaddr)]

        page_dir = self.dtb + ((vaddr >> 21) * 8)

        pgd_pte = self.dtb + self.pgdir_offset(page_dir)

        ret = self.read_long_phys(pgd_pte)

        return ret

    def pmd_page_addr(self, pde_value):

        # CHECK HERE
        #return (pde_value & 0xfffff800) + 2048
        return pde_value & 0xfffff000

    def get_pte_crash(self, vaddr, pde_value):

        debug.debug("Getting crash", 4)
        #page_table = (ulong *)PTOV(pmd_page_addr(pmd_pte)) + PTE_OFFSET(vaddr);
        #pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));

        #*paddr = PAGEBASE(pte) + PAGEOFFSET(vaddr);

        pte_offset = (vaddr >> 12) & 255 #! !!!sdaf

        page_table = ((pde_value >> 10) << 10) + (pte_offset * 4)

        pte = self.read_long_phys(page_table)

        if pte:
            pte_addr = pte + ((page_table & 0xfff) * 4)
        else:
            pte_addr = None

        return pte_addr

    def get_pte(self, vaddr, pde_value):

        # page table
        if (pde_value & 0b11) == 0b01:
            pte_addr = self.get_pte_crash(vaddr, pde_value)

        elif (pde_value & 0b11) == 0b10:

            debug.debug("super", 4)
            issuper = int(pde_value & (1 << 18))

            if not issuper:
                p = pde_value & 0xfffff000
                v = vaddr & 0x1fffff
                debug.debug("{:x} + {:x} = {:x}".format(p, v, p + v), 4)
                pte_addr = p + v
            else:
                debug.warning("super page found")
                return None

        else:
            debug.warning("get_pte: invalid pde_value {:x}".format(pde_value))
            return None


        return pte_addr

    def get_phys_addr(self, vaddr, pte_value):

        return (pte_value & 0xfffff000) | (vaddr & 0xfff)

    def vtop(self, vaddr):

        debug.debug("\n--vtop start: {:x}".format(vaddr), 4)

        pde_value = self.get_pde(vaddr)

        if not pde_value:
            debug.debug("no pde_value", 4)
            return None

        debug.debug("!!!pde_value: {:x}".format(pde_value), 4)

        pte_value = self.get_pte_wrap(pde_value, vaddr)

        if pte_value:
            ret = self.get_phys_addr(vaddr, pte_value)
        else:
            ret = None

        if ret:
            debug.debug("vtop ret {:x}".format(ret), 4)

        return ret

    def get_pte_wrap(self, pde_value, vaddr):

        pte_value = self.get_pte(vaddr, pde_value)

        debug.debug("pte_value: {:x}".format(pte_value), 4)

        if not self.page_table_present(pte_value):
            # Add support for paged out PTE
            #print "page table not present"
            return None

        return pte_value

    # FIXME
    # this is supposed to return all valid physical addresses based on the current dtb
    # this (may?) be painful to write due to ARM's different page table types and having small & large pages inside of those
    def get_available_pages(self):

        for i in xrange(0, (2 ** 32) - 1, 4096):
            yield (i, 0x1000)



