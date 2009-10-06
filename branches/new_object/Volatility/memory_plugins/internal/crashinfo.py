'''
Created on 3 Oct 2009

@author: Mike Auty
'''

import os
import forensics.utils as utils
import forensics.commands as commands
import forensics.conf as conf
config = conf.ConfObject()

class crashinfo(commands.command):
    """Dump crash-dump information"""
    
    def calculate(self):
        """Determines the address space"""
        addr_space = utils.load_as()

        result = None
        adrs = addr_space
        while adrs:
            if adrs.__class__.__name__ == 'WindowsCrashDumpSpace32':
                result = adrs
            adrs = adrs.base
        
        if result is None:
            config.error("Memory Image could not be identified as a crash dump")
        
        return result
            
    def render_text(self, outfd, data):
        """Renders the crashdump header as text"""
        
        hdr = data.get_header()
        
        outfd.write("DUMP_HEADER32:\n")
        outfd.write(" Majorversion:         0x%08x (%s)\n" % (hdr.MajorVersion, hdr.MajorVersion))
        outfd.write(" Minorversion:         0x%08x (%s)\n" % (hdr.MinorVersion, hdr.MinorVersion))
        outfd.write(" KdSecondaryVersion    0x%08x\n" % hdr.KdSecondaryVersion)
        outfd.write(" DirectoryTableBase    0x%08x\n" % hdr.DirectoryTableBase)
        outfd.write(" PfnDataBase           0x%08x\n" % hdr.PfnDataBase)
        outfd.write(" PsLoadedModuleList    0x%08x\n" % hdr.PsLoadedModuleList)
        outfd.write(" PsActiveProcessHead   0x%08x\n" % hdr.PsActiveProcessHead)
        outfd.write(" MachineImageType      0x%08x\n" % hdr.MachineImageType)
        outfd.write(" NumberProcessors      0x%08x\n" % hdr.NumberProcessors)
        outfd.write(" BugCheckCode          0x%08x\n" % hdr.BugCheckCode)
        outfd.write(" PaeEnabled            0x%08x\n" % hdr.PaeEnabled)
        outfd.write(" KdDebuggerDataBlock   0x%08x\n" % hdr.KdDebuggerDataBlock)
        outfd.write(" ProductType           0x%08x\n" % hdr.ProductType)
        outfd.write(" SuiteMask             0x%08x\n" % hdr.SuiteMask)
        outfd.write(" WriterStatus          0x%08x\n" % hdr.WriterStatus)
 
        outfd.write("\nPhysical Memory Description:\n")
        outfd.write("Number of runs: %d\n" % len(data.get_runs()))
        outfd.write("FileOffset    Start Address    Length\n")
        foffset = 0x1000
        run = []
        for run in data.get_runs():
            outfd.write("%08x      %08x         %08x\n" % (foffset, run[0]*0x1000, run[1]*0x1000))
            foffset += (run[1] * 0x1000)
        outfd.write("%08x      %08x\n" % (foffset-0x1000, ((run[0]+run[1]-1)*0x1000)))

class crashdump(crashinfo):
    """Dumps the crashdump file to a raw file"""

    def __init__(self, *args):
        config.add_option("DUMP_FILE", short_option="D", default=None,
                          help = "Specifies the output dump file")
        crashinfo.__init__(self, *args)
    
    def render_text(self, outfd, data):
        """Renders the text output of crashdump file dumping"""
        if not config.DUMP_FILE:
            config.error("crashdump requires an output file to dump the crashdump file")
        
        if os.path.exists(config.DUMP_FILE):
            config.error("File " + config.DUMP_FILE + " already exists, please choose another file or delete it first")
        
        outfd.write("Converting crashdump file...\n")
        
        f = open(config.DUMP_FILE, 'wb')
        total = data.get_number_of_pages()
        for pagenum in data.convert_to_raw(f):
            outfd.write("\r" + ("%08x" % pagenum) + " / " + ("%08x" % total) + " converted (" + ("%03d" % (pagenum * 100 / total)) + "%)")
        f.close()
        outfd.write("\n")