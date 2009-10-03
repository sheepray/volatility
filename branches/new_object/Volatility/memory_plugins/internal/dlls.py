'''
Created on 26 Sep 2009

@author: Mike Auty
'''

#pylint: disable-msg=C0111

import forensics
import forensics.win32 as win32
import forensics.object2 as object2
import forensics.utils as utils
import files

config = forensics.conf.ConfObject()

class dlllist(files.files):
    """Print list of loaded dlls for each process"""

    def render_text(self, outfd, data):
        for task in data:
            pid = task.UniqueProcessId
            ## Skip unwanted processes
            if config.PID and pid != config.PID: continue

            outfd.write("*" * 72 + "\n")
            outfd.write("%s pid: %-6d\n" % (task.ImageFileName, pid))

            if task.Peb:
                outfd.write("Command line : %s\n" % (task.Peb.ProcessParameters.CommandLine))
                outfd.write("%s\n" % task.Peb.CSDVersion)
                outfd.write("\n")
                outfd.write("%-12s %-12s %s\n" % ('Base', 'Size', 'Path'))
                for m in self.list_modules(task):
                    outfd.write("0x%0.8x   0x%0.6x     %s\n" % (m.BaseAddress, m.SizeOfImage, m.FullDllName))
            else:
                print task.Peb
                outfd.write("Unable to read PEB for task.\n")

    def list_modules(self, task):
        if task.UniqueProcessId and task.Peb.Ldr.InLoadOrderModuleList:
            for l in task.Peb.Ldr.InLoadOrderModuleList.list_of_type(
                "_LDR_MODULE", "InLoadOrderModuleList"):
                yield l

    def calculate(self):
        addr_space = utils.load_as()

        if config.OFFSET != None:
            tasks = [object2.NewObject("_EPROCESS", config.OFFSET, addr_space)]
        else:
            tasks = win32.tasks.pslist(addr_space)
        
        return tasks
