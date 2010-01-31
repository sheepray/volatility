# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2004,2005,2006 4tphi Research
#
# Authors:
# {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
# Michael Cohen <scudette@users.sourceforge.net>
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

""" These are standard address spaces supported by Volatility """
import struct
import xml.etree.cElementTree as etree
import volatility.addrspace as addrspace
import volatility.obj as obj 
import volatility.conf
config = volatility.conf.ConfObject()
import volatility.debug as debug #pylint: disable-msg=W0611
import urllib
import os

#pylint: disable-msg=C0111

## This module requires a filename to be passed by the user
config.add_option("USE-OLD-AS", action="store_true", default=False, 
                  help = "Use the legacy address spaces")

def write_callback(option, _opt_str, _value, parser, *_args, **_kwargs):
    """Callback function to ensure that write support is only enabled if user repeats a long string
    
       This call back checks whether the user really wants write support and then either enables it
       (for all future parses) by changing the option to store_true, or disables it permanently
       by ensuring all future attempts to store the value store_false.
    """
    if not hasattr(parser.values, 'write'):
        # We don't want to use config.outfile, since this should always be seen by the user
        option.dest = "write"
        option.action = "store_false"
        parser.values.write = False
        for _ in range(3):
            testphrase = "Yes, I want to enable write support"
            response = raw_input("Write support requested.  Please type \"" + testphrase +
                                 "\" below precisely (case-sensitive):\n")
            if response == testphrase:
                option.action = "store_true"
                parser.values.write = True
                return
        print "Write support disabled."

config.add_option("WRITE", short_option='w', action="callback", default=False,
                  help = "Enable write support", callback=write_callback)

class FileAddressSpace(addrspace.BaseAddressSpace):
    """ This is a direct file AS.

    For this AS to be instanitiated, we need

    1) A valid config.FILENAME

    2) no one else has picked the AS before us
    
    3) base == None (we dont operate on anyone else so we need to be
    right at the bottom of the AS stack.)
    """
    ## We should be the AS of last resort
    order = 100
    def __init__(self, base, layered=False, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, **kwargs)
        assert base == None or layered, 'Must be first Address Space'
        if not config.FILENAME:
            assert config.LOCATION and config.LOCATION.startswith("file:"), 'Location %s is not of file scheme' % config.LOCATION
            path = urllib.url2pathname(config.LOCATION[5:])
        else:
            path = config.FILENAME

        assert os.path.exists(path), 'Filename must be specified and exist'
        self.name = os.path.abspath(path)
        self.fname = self.name
        self.mode = 'rb'
        if config.WRITE:
            self.mode += '+'
        self.fhandle = open(self.fname, self.mode)
        self.fhandle.seek(0, 2)
        self.fsize = self.fhandle.tell()
        self.offset = 0

    def render_xml(self):
        """Renders the Address Space as XML"""
        result = etree.Element('address_space', {'type': self.__class__.__name__,
                                                 'name': self.name})
        location = etree.Element('location')
        location.text = config.LOCATION
        result.append(location)
        return result
    
    def fread(self, length):
        return self.fhandle.read(length)

    def read(self, addr, length):
        self.fhandle.seek(addr)        
        return self.fhandle.read(length)    

    def zread(self, addr, length):
        return self.read(addr, length)

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def get_address_range(self):
        return [0, self.fsize-1]

    def get_available_addresses(self):
        return [0, self.get_address_range()]

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return addr < self.fsize - 1

    def close(self):
        self.fhandle.close()

    def write(self, addr, data):
        if not config.WRITE:
            return False
        try:
            self.fhandle.seek(addr)
            self.fhandle.write(data)
        except IOError:
            return False
        return True

BLOCKSIZE = 1024 * 1024 * 10

## This stuff needs to go in the profile
entry_size = 8
pointer_size = 4
page_shift = 12 
ptrs_per_pte = 1024
ptrs_per_pgd = 1024
ptrs_per_pae_pte = 512
ptrs_per_pae_pgd = 512
ptrs_per_pdpi = 4
pgdir_shift = 22
pdpi_shift = 30
pdptb_shift = 5
pde_shift = 21
ptrs_per_pde = 512
ptrs_page = 2048

config.add_option("DTB", type='int', default=0,
                  help = "DTB Address")

class WritablePagedMemory(addrspace.BaseAddressSpace):
    """
    Mixin class that can be used to add write functionality
    to any standard address space that supports write() and
    vtop().
    """
    def __init__(self, base, **kwargs):
        assert self.__class__.__name__ != 'WritablePagedMemory', "Abstract Class - Never for instantiation directly"
        addrspace.BaseAddressSpace.__init__(self, base)
    
    def write(self, vaddr, buf):
        if not config.WRITE:
            return False
       
        length = len(buf)
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)
        if paddr == None:        
            return False
        
        if length < first_block:
            return self.base.write(paddr, buf)

        self.base.write(paddr, buf[:first_block])
        buf = buf[first_block:]

        new_vaddr = vaddr + first_block
        for _i in range(0, full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                raise Exception("Failed to write to page at {0:#x}".format(new_vaddr))
            if not self.base.write(paddr, buf[:0x1000]):
                return False
            new_vaddr = new_vaddr + 0x1000
            buf = buf[0x1000:]

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr == None:
                raise Exception("Failed to write to page at {0:#x}".format(new_vaddr))
            assert len(buf) == left_over
            return self.base.write(paddr, buf)

    def write_long_phys(self, addr, val):
        if not config.WRITE:
            return False
        buf = struct.pack('=L', val)
        return self.base.write(addr, buf)
    
    def vtop(self, addr):
        """Abstract function that converts virtual (paged) addresses to physical addresses"""
        pass

class IA32PagedMemory(addrspace.BaseAddressSpace, WritablePagedMemory):
    """ Legacy x86 non PAE address space (to use specify --use_old_as)

    We accept an optional arg called dtb to force us to use a
    specific dtb. If not provided, we try to find it from our base
    AS, and failing that we search for it.
    """
    order = 90
    pae = False
    def __init__(self, base, dtb=0, astype = None, **kwargs):
        assert config.USE_OLD_AS, "Module disabled"
        
        WritablePagedMemory.__init__(self, base)
        addrspace.BaseAddressSpace.__init__(self, base, **kwargs)
        assert astype != 'physical', "User requested physical AS"
        
        ## We must be stacked on someone else:
        assert base, "No base Address Space"
        
        ## We can not stack on someone with a page table
        assert not hasattr(base, 'pgd_vaddr'), "Can not stack over page table AS"
        self.pgd_vaddr = dtb or config.DTB or self.load_dtb()

        ## Finally we have to have a valid PsLoadedModuleList
        # FIXME: !!!!! Remove Hardcoded HACK!!!!
        assert self.is_valid_address(0x8055a420), "PsLoadedModuleList not valid Address"

    def load_dtb(self):
        try:
            ## Try to be lazy and see if someone else found dtb for
            ## us:
            return self.base.dtb
        except AttributeError:
            ## Ok so we need to find our dtb ourselves:
            dtb = self._find_dtb()
            if dtb:
                ## Make sure to save dtb for other AS's
                self.base.dtb = dtb
                return dtb

    def _find_dtb(self):
        offset = 0
        while 1:
            data = self.base.read(offset, BLOCKSIZE)
            found = 0
            if not data:
                break
            
            while 1:
                found = data.find("\x03\x00\x1b\x00", found+1)
                if found >= 0:
                    # (_type, _size) = unpack('=HH', data[found:found+4])
                    proc = obj.Object("_EPROCESS",
                                             offset = offset+found,
                                             vm=self.base)

                    if 'Idle' in proc.ImageFileName.v():
                        return proc.Pcb.DirectoryTableBase[0]
                else:
                    break

            offset += len(data)

        return None

    def entry_present(self, entry):
        if (entry & (0x00000001)) == 0x00000001:
            return True
        return False

    def page_size_flag(self, entry):
        if (entry & (1 << 7)) == (1 << 7):
            return True
        return False    

    def pgd_index(self, pgd):
        return (pgd >> pgdir_shift) & (ptrs_per_pgd - 1)

    def get_pgd(self, vaddr):
        pgd_entry = self.pgd_vaddr + self.pgd_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte >> page_shift

    def pte_index(self, pte):
        return (pte >> page_shift) & (ptrs_per_pte - 1)

    def get_pte(self, vaddr, pgd):
        pgd_val = pgd & ~((1 << page_shift) - 1)
        pgd_val = pgd_val + self.pte_index(vaddr) * pointer_size
        return self.read_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return (self.pte_pfn(pte) << page_shift) | (vaddr & ((1 << page_shift) - 1))

    def get_four_meg_paddr(self, vaddr, pgd_entry):
        return (pgd_entry & ((ptrs_per_pgd-1) << 22)) | (vaddr & ~((ptrs_per_pgd-1) << 22))

    def vtop(self, vaddr):
        retVal = None
        pgd = self.get_pgd(vaddr)
        if self.entry_present(pgd):
            if self.page_size_flag(pgd):
                retVal =  self.get_four_meg_paddr(vaddr, pgd)
            else:
                pte = self.get_pte(vaddr, pgd)
                if not pte:
                    return None
                if self.entry_present(pte):
                    retVal =  self.get_paddr(vaddr, pte)
        return retVal

    def read(self, vaddr, length):
        length = int(length)
        vaddr = int(vaddr)

        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)
        if paddr == None:        
            return None
        
        if length < first_block:
            stuff_read = self.base.read(paddr, length)
            if stuff_read == None:
                return None
            return stuff_read

        stuff_read = self.base.read(paddr, first_block)
        if stuff_read == None:
            return None

        new_vaddr = vaddr + first_block
        for _i in range(0, full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr is None:
                return None
            new_stuff = self.base.read(paddr, 0x1000)
            if new_stuff is None:
                return None
            stuff_read = stuff_read + new_stuff
            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr is None:
                return None
            new_stuff = self.base.read(paddr, left_over)
            if new_stuff is None:
                return None
            stuff_read = stuff_read + new_stuff
        return stuff_read

    def zread(self, vaddr, length):
        length = int(length)
        vaddr = int(vaddr)
        first_block = 0x1000 - vaddr % 0x1000
        full_blocks = ((length + (vaddr % 0x1000)) / 0x1000) - 1
        left_over = (length + vaddr) % 0x1000
        
        paddr = self.vtop(vaddr)

        if paddr is None:
            if length < first_block:
                return ('\0' * length)
            stuff_read = ('\0' * first_block)       
        else:
            if length < first_block:
                return self.base.zread(paddr, length)
            stuff_read = self.base.zread(paddr, first_block)

        new_vaddr = vaddr + first_block
        for _i in range(0, full_blocks):
            paddr = self.vtop(new_vaddr)
            if paddr is None:
                stuff_read = stuff_read + ('\0' * 0x1000)
            else:
                stuff_read = stuff_read + self.base.zread(paddr, 0x1000)

            new_vaddr = new_vaddr + 0x1000

        if left_over > 0:
            paddr = self.vtop(new_vaddr)
            if paddr is None:
                stuff_read = stuff_read + ('\0' * left_over)
            else:
                stuff_read = stuff_read + self.base.zread(paddr, left_over)
        return stuff_read

    def read_long_virt(self, addr):
        string = self.read(addr, 4)
        if string is None:
            return None
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def read_long_phys(self, addr):
        string = self.base.read(addr, 4)
        if string is None:
            return None
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def is_valid_address(self, addr):
        if addr == None:
            return False
        try:    
            phyaddr = self.vtop(addr)
        except:
            return False
        if phyaddr == None:
            return False
        if not self.base.is_valid_address(phyaddr):
            return False
        return True

    def get_available_pages(self):
        pgd_curr = self.pgd_vaddr
        for i in range(0, ptrs_per_pgd):
            start = (i * ptrs_per_pgd * ptrs_per_pte * 4)
            entry = self.read_long_phys(pgd_curr)
            pgd_curr = pgd_curr + 4
            if self.entry_present(entry) and self.page_size_flag(entry):
                yield [start, 0x400000]
            elif self.entry_present(entry):
                pte_curr = entry & ~((1 << page_shift)-1)                
                for j in range(0, ptrs_per_pte):
                    pte_entry = self.read_long_phys(pte_curr)
                    pte_curr = pte_curr + 4
                    if self.entry_present(pte_entry):
                        yield [start + j * 0x1000, 0x1000]

class IA32PagedMemoryPae(IA32PagedMemory):
    """ Legacy x86 PAE address space (to use specify --use_old_as)
    """
    order = 80
    pae = True
    def __init__(self, base, **kwargs):
        """ We accept an optional arg called dtb to force us to use a
        specific dtb. If not provided, we try to find it from our base
        AS, and failing that we search for it.
        """
        IA32PagedMemory.__init__(self, base, **kwargs)
        
    def get_pdptb(self, pdpr):
        return pdpr & 0xFFFFFFE0

    def pdpi_index(self, pdpi):
        return (pdpi >> pdpi_shift)

    def get_pdpi(self, vaddr):
        pdpi_entry = self.get_pdptb(self.pgd_vaddr) + self.pdpi_index(vaddr) * entry_size
        return self.read_long_long_phys(pdpi_entry)

    def pde_index(self, vaddr):
        return (vaddr >> pde_shift) & (ptrs_per_pde - 1)

    def pdba_base(self, pdpe):
        return pdpe & 0xFFFFFF000

    def get_pgd(self, vaddr, pdpe):
        pgd_entry = self.pdba_base(pdpe) + self.pde_index(vaddr) * entry_size
        return self.read_long_long_phys(pgd_entry)

    def pte_pfn(self, pte):
        return pte & 0xFFFFFF000

    def pte_index(self, vaddr):
        return (vaddr >> page_shift) & (ptrs_per_pde - 1)

    def ptba_base(self, pde):
        return pde & 0xFFFFFF000

    def get_pte(self, vaddr, pgd):
        pgd_val = self.ptba_base(pgd) + self.pte_index(vaddr) * entry_size
        return self.read_long_long_phys(pgd_val)

    def get_paddr(self, vaddr, pte):
        return self.pte_pfn(pte) | (vaddr & ((1 << page_shift) - 1))

    def get_large_paddr(self, vaddr, pgd_entry):
        return (pgd_entry & 0xFFE00000) | (vaddr & ~((ptrs_page-1) << 21))

    def vtop(self, vaddr):
        retVal = None
        pdpe = self.get_pdpi(vaddr)

        if not self.entry_present(pdpe):
            return retVal

        pgd = self.get_pgd(vaddr, pdpe)
        if self.entry_present(pgd):
            if self.page_size_flag(pgd):
                retVal = self.get_large_paddr(vaddr, pgd)
            else:
                pte = self.get_pte(vaddr, pgd)
                if self.entry_present(pte):
                    retVal =  self.get_paddr(vaddr, pte)
                        
        return retVal

    def read_long_long_phys(self, addr):
        string = self.base.read(addr, 8)
        if string == None:
            return None
        (longlongval, ) = struct.unpack('=Q', string)
        return longlongval

    def get_available_pages(self):
       
        pdpi_base = self.get_pdptb(self.pgd_vaddr)

        for i in range(0, ptrs_per_pdpi): 

            start = (i * ptrs_per_pae_pgd * ptrs_per_pae_pgd * ptrs_per_pae_pte * 8)
            pdpi_entry  = pdpi_base + i * entry_size        
            pdpe = self.read_long_long_phys(pdpi_entry)

            if not self.entry_present(pdpe):
                continue
          
            pgd_curr = self.pdba_base(pdpe)          
                  
            for j in range(0, ptrs_per_pae_pgd):
                soffset = start + (j * ptrs_per_pae_pgd * ptrs_per_pae_pte * 8)
                entry = self.read_long_long_phys(pgd_curr)
                pgd_curr = pgd_curr + 8
                if self.entry_present(entry) and self.page_size_flag(entry):
                    yield [soffset, 0x200000]
                elif self.entry_present(entry):
                    pte_curr = entry & ~((1 << page_shift)-1)                
                    for k in range(0, ptrs_per_pae_pte):
                        pte_entry = self.read_long_long_phys(pte_curr)
                        pte_curr = pte_curr + 8
                        if self.entry_present(pte_entry):
                            yield [soffset + k * 0x1000, 0x1000]
