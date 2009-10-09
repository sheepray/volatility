'''
Created on 8 Oct 2009

@author: Mike Auty
'''

import os
import taskmods
import forensics
import forensics.object2 as object2
config = forensics.conf.ConfObject()

class procexedump(taskmods.dlllist):
    """Dump a process to an executable file sample"""
    
    def __init__(self, *args):
        config.add_option('DUMP_DIR', short_option='D', default=None,
                          help='Directory in which to dump the VAD files')
        config.add_option("UNSAFE", short_option="u", default=0, type='int',
                          help='Bypasses certain sanity checks when creating image')
        taskmods.dlllist.__init__(self, *args)

    def calculate(self):
        """Calculates a dictionary of tasks associated by their pid"""
        result = {}
        tasks = taskmods.dlllist.calculate(self)
        
        for task in tasks:
            if task.UniqueProcessId:
                pid = task.UniqueProcessId
                if (not config.PID) or pid == config.PID:
                    result[pid] = {'task': task}

        return result

    def render_text(self, outfd, data):
        """Renders the tasks to disk images, outputting progress as they go"""
        if config.DUMP_DIR == None:
            config.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(config.DUMP_DIR):
            config.error(config.DUMP_DIR + " is not a directory")        
        
        for pid in data:
            outfd.write("*" * 72 + "\n")
            task = data[pid]['task']
            task_space = task.get_process_address_space()
            if task.Peb == None:
                outfd.write("Error: PEB not memory resident for process [%d]\n" % (pid))
                continue
            if task.Peb.ImageBaseAddress == None or task_space == None or task_space.vtop(task.Peb.ImageBaseAddress) == None:
                outfd.write("Error: ImageBaseAddress not memory resident for process [%d]\n" % (pid))
                continue

            outfd.write("Dumping %s, pid: %-6d output: %s\n" % (task.ImageFileName, pid, "executable." + str(pid) + ".exe"))
            of = open(os.path.join(config.DUMP_DIR, "executable." + str(pid) + ".exe"), 'wb')
            try:
                for chunk in self.get_image(outfd, task):
                    offset, code = chunk
                    of.seek(offset)
                    of.write(code)
            except ValueError, ve:
                outfd.write("Unable to dump executable; sanity check failed:\n")
                outfd.write("  " + str(ve) + "\n")
                outfd.write("You can use -u to disable this check.\n")
            of.close()

    def round(self, addr, align, down=True):
        """Rounds down an address based on an alignment"""
        addr = int(addr)
        align = int(align)
        if addr % align == 0: 
            return addr
        else: 
            if down:
                return (addr - (addr % align))
            else:
                return (addr + (align - (addr % align)))

    def get_nt_header(self, task):
        """Returns the NT Header object for a task"""
        task_space = task.get_process_address_space()
        dos_header = object2.NewObject("_IMAGE_DOS_HEADER", task.Peb.ImageBaseAddress, task_space)
        nt_header = object2.NewObject("_IMAGE_NT_HEADERS", task.Peb.ImageBaseAddress + int(dos_header.e_lfanew), task_space)
        return nt_header, task_space

    def get_sectors(self, task):
        """Returns the sectors from a process"""
        nt_header, task_space = self.get_nt_header(task)
        
        sect_size = task_space.profile.get_obj_size("_IMAGE_SECTION_HEADER")
        start_addr = int(nt_header.OptionalHeader.offset) + int(nt_header.FileHeader.SizeOfOptionalHeader) 
        
        for i in range(nt_header.FileHeader.NumberOfSections):
            s_addr = start_addr + (i * sect_size)
            sect = object2.NewObject("_IMAGE_SECTION_HEADER", s_addr, task_space)
            if not config.UNSAFE:
                self.sanity_check_section(sect, nt_header.OptionalHeader.SizeOfImage)
            yield sect

    def sanity_check_section(self, sect, image_size):
        """Sanity checks address boundaries"""
        # Note: all addresses here are RVAs
        image_size = int(image_size)
        if int(sect.VirtualAddress) > image_size:
            raise ValueError('VirtualAddress %08x is past the end of image.' %
                                    sect.VirtualAddress)
        if int(sect.Misc.VirtualSize) > image_size:
            raise ValueError('VirtualSize %08x is larger than image size.' %
                                    sect.Misc.VirtualSize)
        if int(sect.SizeOfRawData) > image_size:
            raise ValueError('SizeOfRawData %08x is larger than image size.' %
                                    sect.SizeOfRawData)
        
    def get_code(self, task_space, data_start, data_size, offset, outfd):
        """Returns the file re-created data from a file"""
        first_block = 0x1000 - data_start % 0x1000
        full_blocks = ((data_size + (data_start % 0x1000)) / 0x1000) - 1
        left_over = (data_size + data_start) % 0x1000

        paddr = task_space.vtop(data_start)
        code = ""
    
        # Deal with reads that are smaller than a block
        if data_size < first_block:
            data_read = task_space.zread(data_start, data_size)
            if paddr == None:
                outfd.write("Memory Not Accessible: Virtual Address: 0x%x File Offset: 0x%x Size: 0x%x\n" % (data_start, offset, data_size))
            code += data_read
            return (offset, code)
                
        data_read = task_space.zread(data_start, first_block)
        if paddr == None:
            outfd.write("Memory Not Accessible: Virtual Address: 0x%x File Offset: 0x%x Size: 0x%x\n" % (data_start, offset, first_block))
        code += data_read
    
        # The middle part of the read
        new_vaddr = data_start + first_block
    
        for _i in range(0, full_blocks):
            data_read = task_space.zread(new_vaddr, 0x1000)
            if task_space.vtop(new_vaddr) == None:
                outfd.write("Memory Not Accessible: Virtual Address: 0x%x File Offset: 0x%x Size: 0x%x\n" % (new_vaddr, offset, 0x1000))
            code += data_read
            new_vaddr = new_vaddr + 0x1000        
    
        # The last part of the read
        if left_over > 0:
            data_read = task_space.zread(new_vaddr, left_over)
            if task_space.vtop(new_vaddr) == None:
                outfd.write("Memory Not Accessible: Virtual Address: 0x%x File Offset: 0x%x Size: 0x%x\n" % (new_vaddr, offset, left_over))       
            code += data_read
        return (offset, code)

    def get_image(self, outfd, task):
        """Outputs an executable disk image of a process"""
        iba = task.Peb.ImageBaseAddress
        nt_header, task_space = self.get_nt_header(task)

        soh = nt_header.OptionalHeader.SizeOfHeaders
        header = task_space.read(iba, soh)
        yield (0, header)
        
        fa = nt_header.OptionalHeader.FileAlignment
        for sect in self.get_sectors(task):
            foa = self.round(sect.PointerToRawData, fa)
            if foa != int(sect.PointerToRawData):
                outfd.write("Warning: section start on disk not aligned to file alignment.\n")
                outfd.write("Warning: adjusted section start from %x to %x.\n" % (int(sect.PointerToRawData), foa))
            offset, code = self.get_code(task_space, int(iba + sect.VirtualAddress), int(sect.SizeOfRawData), foa, outfd)
            yield offset, code
    
#class procmemdump(procexedump):
#    """Dump a process to an executable memory sample"""
#    
#    def get_image(self, outfd, task, sect):
#        iba = task.Peb.ImageBaseAddress
#        nt_header, task_space = self.get_nt_header(task)
#
#        sa = nt_header.OptionalHeader.SectionAlignment
#        soh = nt_header.OptionalHeader.SizeOfHeaders
#        shs = task_space.profile.get_obj_size('_IMAGE_SECTION_HEADER')
#
#        yield self.get_code(task_space, iba, nt_header.OptionalHeader.SizeOfImage, 0)
#
#        counter = 0
#        for sect in self.get_sectors(task):
#            sectheader = task_space.read(sect.offset, shs)
#            nt_header.OptionalHeader.offset + int(soh) + (counter * shs)
#            counter += 1
#            yield ()