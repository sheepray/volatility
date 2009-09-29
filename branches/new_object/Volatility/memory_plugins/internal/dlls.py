'''
Created on 26 Sep 2009

@author: Mike Auty
'''

#pylint: disable-msg=C0111

import forensics
import forensics.win32 as win32
import forensics.object2 as object2
import forensics.utils as utils

config = forensics.conf.ConfObject()

config.add_option('OFFSET', short_option = 'o', default=None,
    help='EPROCESS Offset (in hex) in physical address space',
    action='store', type='string')

config.add_option('PID', short_option = 'p',
    help='Get info for this Pid', default=None,
    action='store', type='int')

class dlllist(forensics.commands.command):
    """Print list of loaded dlls for each process"""

    def render_text(self, outfd, data):
        first = True
        for pid in data:
            if not first:
                outfd.write("*" * 72 + "\n")

            task = data[pid]['task']
            outfd.write("%s pid: %-6d\n" % (task.ImageFileName, pid))
            first = False

            if task.Peb:
                outfd.write("Command line : %s\n" % (task.Peb.ProcessParameters.CommandLine))
                outfd.write("%s\n" % task.Peb.CSDVersion)
                outfd.write("\n")
                modules = data[pid]['modules']
                outfd.write("%-12s %-12s %s\n" % ('Base', 'Size', 'Path'))
                for m in modules:
                    outfd.write("0x%0.8x   0x%0.6x     %s\n" % (int(m.BaseAddress), int(m.SizeOfImage), m.FullDllName))
            else:
                print task.Peb
                outfd.write("Unable to read PEB for task.\n")

    def calculate(self):
        result = {}
        addr_space = utils.load_as()
        
        if config.OFFSET:
            try:
                offset = int(config.OFFSET, 16)
            except ValueError:
                config.error("EPROCESS offset must be a hexadecimal number.")
            
            tasks = [object2.NewObject("_EPROCESS", offset, addr_space)]

        else:
            tasks = win32.tasks.pslist(addr_space)
        
        for task in tasks:
            if task.UniqueProcessId:
                pid = int(task.UniqueProcessId)
                if config.PID and pid != config.PID:
                    continue
                
                result[pid] = {'task': task, 'modules': []}

                if task.Peb.Ldr.InLoadOrderModuleList:
                    for l in task.Peb.Ldr.InLoadOrderModuleList.list_of_type("_LDR_MODULE", "InLoadOrderModuleList"):
                        result[pid]['modules'].append(l)

        return result
