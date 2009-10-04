'''
Created on 26 Sep 2009

@author: Mike Auty
'''

#pylint: disable-msg=C0111

import forensics.commands
import forensics.win32 as win32
import forensics.object2 as object2
import forensics.utils as utils
import forensics.conf as conf

config = conf.ConfObject()


class files(forensics.commands.command):
    """Print list of open files for each process"""

    def __init__(self, *args):
        config.add_option('OFFSET', short_option = 'o', default=None,
                          help='EPROCESS Offset (in hex) in physical address space',
                          action='store', type='int')
        
        config.add_option('PID', short_option = 'p',
                          help='Get info for this Pid', default=None,
                          action='store', type='int')
        
        forensics.commands.command.__init__(self, *args)

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
        addr_space = utils.load_as()
        
        if config.OFFSET != None:
            tasks = [object2.NewObject("_EPROCESS", config.OFFSET, addr_space)]
        else:
            tasks = win32.tasks.pslist(addr_space)
        
        for task in tasks:
            if task.ObjectTable.HandleTableList:
                pid = int(task.ObjectTable.UniqueProcessId)
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
