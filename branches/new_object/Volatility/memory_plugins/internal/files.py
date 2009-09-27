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

    def __init__(self, args=None):
        forensics.commands.command.__init__(self, args)
        self.profile = None

    def parser(self):
        """Sets up the parser before execution"""
        forensics.commands.command.parser(self)

        self.op.add_option('-o', '--offset',
            help='EPROCESS Offset (in hex) in physical address space',
            action='store', type='string', dest='offset')

        self.op.add_option('-p', '--pid',
            help='Get info for this Pid', default=None,
            action='store', type='int', dest='pid')

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
        
        if config.OFFSET:
            try:
                offset = int(self.opts.offset, 16)
            except ValueError:
                self.op.error("EPROCESS offset must be a hexadecimal number.")
            
            tasks = [object2.NewObject("_EPROCESS", offset, addr_space, profile=self.profile)]

        else:
            tasks = win32.tasks.pslist(addr_space, self.profile)
        
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
