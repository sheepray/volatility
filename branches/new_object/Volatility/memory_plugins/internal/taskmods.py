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

class dlllist(forensics.commands.command):
    """Print list of loaded dlls for each process"""

    def __init__(self, *args):
        config.add_option('OFFSET', short_option = 'o', default=None,
                          help='EPROCESS Offset (in hex) in physical address space',
                          action='store', type='int')
        
        config.add_option('PID', short_option = 'p',
                          help='Get info for this Pid', default=None,
                          action='store', type='int')
        
        forensics.commands.command.__init__(self, *args)

    def render_text(self, outfd, data):
        for task in data:
            pid = task.UniqueProcessId
            ## Skip unwanted processes
            if config.PID and pid != config.PID:
                continue

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
        """Produces a list of processes, or just a single process based on an OFFSET"""
        addr_space = utils.load_as()

        if config.OFFSET != None:
            tasks = [object2.NewObject("_EPROCESS", config.OFFSET, addr_space)]
        else:
            tasks = win32.tasks.pslist(addr_space)
        
        return tasks

# Inherit from files just for the config options (__init__)
class files(dlllist):
    """Print list of open files for each process"""

    def render_text(self, outfd, data):
        first = True
        for pid in data:
            if not first:
                outfd.write("*" * 72 + "\n")
            outfd.write("Pid: %-6d\n" % pid)
            first = False
            
            handles = data[pid]
            for h in handles:
                if h.FileName:
                    outfd.write("%-6s %-40s\n" % ("File", h.FileName))

    def calculate(self):
        result = {}
        tasks = dlllist.calculate(self)
        
        for task in tasks:
            if task.ObjectTable.HandleTableList:
                pid = task.UniqueProcessId
                if config.PID and pid != config.PID:
                    continue
                handles = task.handles()
                
                # Weed out just the file handles:
                for h in handles:
                    if str(h.Type.Name) == 'File':
                        filevar = object2.NewObject("_FILE_OBJECT", h.Body.offset, task.vm, parent=task, profile=task.profile)
                        hlist = result.get(pid, [])
                        hlist.append(filevar)
                        result[pid] = hlist

        return result

class pslist(dlllist):
    """ print all running processes by following the EPROCESS lists """
    def render_text(self, outfd, data):
        outfd.write("%-20s %-6s %-6s %-6s %-6s %-6s\n" % (
            'Name', 'Pid', 'PPid', 'Thds', 'Hnds', 'Time'))

        for task in data:
            outfd.write("%-20s %-6d %-6d %-6d %-6d %-26s\n" % (
                task.ImageFileName,
                task.UniqueProcessId,
                task.InheritedFromUniqueProcessId,
                task.ActiveThreads,
                task.ObjectTable.HandleCount,
                task.CreateTime))

# Inherit from files just for the config options (__init__)
class memmap(dlllist):
    """Print the memory map"""

    def render_text(self, outfd, data):
        first = True
        for pid in data:
            if not first:
                outfd.write("*" * 72 + "\n")

            task = data[pid]['task']
            task_space = task.get_process_address_space()
            pagedata = data[pid]['pages']
            outfd.write("%s pid: %-6d\n" % (task.ImageFileName, pid))
            first = False

            if pagedata:
                outfd.write("%-12s %-12s %-12s\n" % ('Virtual', 'Physical', 'Size'))

                for p in pagedata:
                    pa = task_space.vtop(p[0])
                    if not pa:
                        outfd.write("0x%-10x 0x000000     0x%-12x\n" % (p[0], p[1]))
                    else:
                        outfd.write("0x%-10x 0x%-10x 0x%-12x\n" % (p[0], pa, p[1]))
            else:
                outfd.write("Unable to read pages for task.\n")

    def calculate(self):
        result = {}
        tasks = dlllist.calculate(self)
        
        for task in tasks:
            if task.UniqueProcessId:
                pid = task.UniqueProcessId
                if (not config.PID) or pid == config.PID:
                    task_space = task.get_process_address_space()
                    pages = task_space.get_available_pages()
                    result[pid] = {'task': task, 'pages': pages}

        return result
