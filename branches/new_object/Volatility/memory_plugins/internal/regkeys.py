'''
Created on 4 Oct 2009

@author: Mike Auty
'''

import taskmods
import forensics.conf

config = forensics.conf.ConfObject()

class regobjkeys2(taskmods.files):
    """Print list of open regkeys for each process"""
    
    def __init__(self, *args):
        taskmods.files.__init__(self, *args)
        self.handle_type = 'Key'
        self.handle_obj = '_CM_KEY_BODY'
    
    def render_text(self, outfd, data):
        first = True
        for pid in data:
            if not first:
                outfd.write("*" * 72 + "\n")
            outfd.write("Pid: %-6d\n" % pid)
            first = False
            
            handles = data[pid]
            for h in handles:
                keyname = self.full_key_name(h)
                outfd.write("%-6s %-40s\n" % ("Key", keyname))
                
    def full_key_name(self, handle):
        """Returns the full name of a registry key based on its CM_KEY_BODY handle"""
        output = []
        kcb = handle.KeyControlBlock
        while kcb.ParentKcb:
            output.append(str(kcb.NameBlock.Name))
            kcb = kcb.ParentKcb
        return "\\".join(reversed(output))
        
