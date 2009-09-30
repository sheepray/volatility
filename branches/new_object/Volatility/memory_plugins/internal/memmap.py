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

class memmap(forensics.commands.command):
    """Print list of loaded dlls for each process"""

    def render_text(self, outfd, data):
        first = True
        for pid in data:
            if not first:
                outfd.write("*" * 72 + "\n")

            task = data[pid]['task']
            pagedata = data[pid]['pages']
            outfd.write("%s pid: %-6d\n" % (task.ImageFileName, pid))
            first = False

            if pagedata:
                outfd.write("%-12s %-12s %-12s\n" % ('Virtual', 'Physical', 'Size'))

                for p in pagedata:
                    if p[1] is None:
                        print "0x%-10x 0x000000     0x%-12x" % (p[0], p[2])
                    outfd.write("0x%-10x 0x%-10x 0x%-12x\n" % p)
            else:
                outfd.write("Unable to read pages for task.\n")

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
                if (not config.PID) or pid == config.PID:
                    res = []
                    task_space = task.get_process_address_space()
                    pages = task_space.get_available_pages()
                    for p in pages:
                        pa = task_space.vtop(p[0])
                        if pa:
                            res.append((p[0], pa, p[1]))
                    result[pid] = {'task': task, 'pages': res}

        return result
