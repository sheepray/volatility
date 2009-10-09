'''
Created on 9 Oct 2009

@author: Mike Auty
'''

import os
import forensics
import forensics.object2 as object2
import forensics.utils as utils
import forensics.win32 as win32
import forensics.conf as conf
config = conf.ConfObject()

class strings(forensics.commands.command):
    """Match physical offsets to virtual addresses (may take a while, VERY verbose)"""
    
    def __init__(self, *args):
        config.add_option('STRING_FILE', short_option = 's', default=None,
                          help='File output in strings format (offset:string)',
                          action='store', type='str')
        config.add_option('PIDS', short_option = 'p', default=None,
                          help='Operate on these Process IDs (comma-separated)',
                          action='store', type='str')
        forensics.commands.command.__init__(self, *args)
    
    def calculate(self):
        """Calculates the physical to virtual address mapping"""
        if config.STRING_FILE is None or not os.path.exists(config.STRING_FILE):
            config.error("Strings file not found")
        
        data = {}
        
        data['addr_space'] = utils.load_as()

        data['tasks'] = win32.tasks.pslist(data['addr_space'])

        try:
            if config.PIDS is not None:
                pidlist = [int(p) for p in config.PIDS.split(',')]
                newtasks = [t for t in data['tasks'] if int(t.UniqueProcessId) in pidlist]
                data['tasks'] = newtasks
        except (ValueError, TypeError):
            # TODO: We should probably print a non-fatal warning here
            pass
                    
        return data

    def render_text(self, outfd, data):
        """Runs through the text file outputting which string appears where"""

        # dict of form phys_page -> [isKernel, (pid1, vaddr1), (pid2, vaddr2) ...]
        # where isKernel is True or False. if isKernel is true, list is of all kernel addresses
        # ASSUMPTION: no pages mapped in kernel and userland
        reverse_map = {}
        
        verbfd = object2.NoneObject("Swallow output unless VERBOSE mode is enabled")
        if config.VERBOSE:
            verbfd = outfd
    
        verbfd.write("Calculating kernel mapping...\n")
        vpage = 0
        while vpage < 0xFFFFFFFF:
            kpage = data['addr_space'].vtop(vpage)
            if not kpage is None:
                # Write the status inside the check for None, so we don't output too often
                if not reverse_map.has_key(kpage):
                    reverse_map[kpage] = [True]
                reverse_map[kpage].append(('kernel', vpage))
            verbfd.write("\r  Kernel [%0.8x]" % vpage)
            vpage += 0x1000
        verbfd.write("\n")
    
        print "Calculating task mappings..."
        for task in data['tasks']:
            task_space = task.get_process_address_space()
            verbfd.write("  Task %d ..." % task.UniqueProcessId)
            vpage = 0
            try:
                while vpage < 0xFFFFFFFF:
                    physpage = task_space.vtop(vpage)
                    if not physpage is None:
                        if not reverse_map.has_key(physpage):
                            reverse_map[physpage] = [False]
    
                        if not reverse_map[physpage][0]:
                            reverse_map[physpage].append((int(task.UniqueProcessId), vpage))
                    verbfd.write("\r  Task %d [%0.8x]" % (task.UniqueProcessId, vpage))
                    vpage += 0x1000
            except:
                continue
            verbfd.write("\n")
        verbfd.write("\n")
            
        stringlist = open(config.STRING_FILE, "r")
        
        for stringLine in stringlist:
            (offsetString, string) = self.parse_line(stringLine)
            try:
                offset = int(offsetString)
            except (ValueError, TypeError):
                config.error("String file format invalid.")
            if reverse_map.has_key(offset & 0xFFFFF000):
                outfd.write("%0.8x [" % offset)
                outfd.write(' '.join(["%s:%x" % (pid[0], pid[1] | (offset & 0xFFF)) for pid in reverse_map[offset & 0xFFFFF000][1:]]))
                outfd.write("] %s\n" % string.strip())

    def parse_line(self, stringLine):
        """Parses a line of strings"""
        space_pos = stringLine[7:].index(' ') + 7
        return (stringLine[:space_pos], stringLine[space_pos + 1:])
        # FIXME: Figure out how to determine whether strings is space separated or colon separated
        # return stringLine.split(':', 1)
