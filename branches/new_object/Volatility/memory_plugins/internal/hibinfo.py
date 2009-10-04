'''
Created on 3 Oct 2009

@author: Mike Auty
'''

import os
import forensics.utils as utils
import forensics.object2 as object2 
import forensics.commands as commands
import forensics.conf as conf
config = conf.ConfObject()

config.add_option("OUTPUT_FILE", short_option="O", default=None,
                  help = "Specifies the output file")

class hibinfo(commands.command):
    """Dump hibernation file information"""
    
    def calculate(self):
        """Determines the address space"""
        addr_space = utils.load_as()
        
        result = None
        adrs = addr_space
        while adrs:
            if adrs.__class__.__name__ == 'WindowsHiberFileSpace32':
                sr = adrs.ProcState.SpecialRegisters

                entrysize = adrs.profile.get_obj_size("_KGDTENTRY")
                entry = object2.NewObject("_KGDTENTRY", sr.Gdtr.Base + ((0x3B >> 3) * entrysize), addr_space) 
                NtTibAddress = (entry.BaseLow) | (entry.BaseMid << (2 * 8)) | (entry.BaseHigh << (3 * 8))

                teb = object2.NoneObject("NtTibAddress out of range")
                if not ((NtTibAddress == 0) or (NtTibAddress > 0x80000000)):
                    teb = object2.NewObject("_TEB", NtTibAddress, addr_space)
                
                result = {'header': adrs.get_header(),
                          'sr': sr,
                          'peb': teb.ProcessEnvironmentBlock,
                          'adrs': adrs }
            adrs = adrs.base
        
        if result is None:
            config.error("Memory Image could not be identified as a hibernation file")
        
        return result
            
    def render_text(self, outfd, data):
        """Renders the hiberfil header as text"""
        
        hdr = data['header']
        sr = data['sr']
        peb = data['peb']
        
        outfd.write("IMAGE_HIBER_HEADER:\n")
        outfd.write(" Signature: %s\n" % hdr.Signature)
        outfd.write(" SystemTime: %s\n" % hdr.SystemTime)
        
        outfd.write("\nControl registers flags\n")
        outfd.write(" CR0: %08x\n" % sr.Cr0)
        outfd.write(" CR0[PAGING]: %d\n" % ((sr.Cr0 >> 31) & 1) )
        outfd.write(" CR3: %08x\n" % sr.Cr3)
        outfd.write(" CR4: %08x\n" % sr.Cr4)
        outfd.write(" CR4[PSE]: %d\n" % ((sr.Cr4 >> 4) & 1) )
        outfd.write(" CR4[PAE]: %d\n" % ((sr.Cr4 >> 5) & 1) )

        outfd.write("\nWindows Version is %d.%d (%d)\n\n" % (peb.OSMajorVersion, peb.OSMinorVersion, peb.OSBuildNumber))
        
class hibdump(hibinfo):
    """Dumps the hibernation file to a raw file"""
    
    def render_text(self, outfd, data):
        """Renders the text output of hibneration file dumping"""
        if not config.OUTPUT_FILE:
            config.error("Hibdump requires an output file to dump the hibernation file")
        
        if os.path.exists(config.OUTPUT_FILE):
            config.error("File " + config.OUTPUT_FILE + " already exists, please choose another file or delete it first")
        
        outfd.write("Converting hibernation file...\n")
        
        f = open(config.OUTPUT_FILE, 'wb')
        total = data['adrs'].get_number_of_pages()
        for pagenum in data['adrs'].convert_to_raw(f):
            outfd.write("\r" + ("%08x" % pagenum) + " / " + ("%08x" % total) + " converted (" + ("%03d" % (pagenum * 100 / total)) + "%)")
        f.close()