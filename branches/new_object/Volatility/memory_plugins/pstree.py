"""pstree example file"""

from forensics.win32.tasks import pslist
import forensics.utils as utils
import forensics.commands
import forensics.conf
config = forensics.conf.ConfObject()

config.add_option("VERBOSE", default=0, type='int',
                  short_option='v', help='Verbose information')

#pylint: disable-msg=C0111

pslist_types = {
    '_SE_AUDIT_PROCESS_CREATION_INFO' : [ 0x4, {
    'ImageFileName' : [ 0x0, ['pointer', ['_OBJECT_NAME_INFORMATION']]],
    } ],
                                      
    '_OBJECT_NAME_INFORMATION' : [ 0x8, {
    'Name' : [ 0x0, ['_UNICODE_STRING']],
    } ],
    }

class pstree(forensics.commands.command):
    """Print process list as a tree"""    

    def find_root(self, pid_dict, pid):
        while pid in pid_dict:
            pid = pid_dict[pid]['inherited_from']
            
        return pid

    def render_text(self, outfd, data):
        outfd.write("%-20s %-6s %-6s %-6s %-6s %-6s\n" %(
            'Name','Pid','PPid','Thds','Hnds','Time'))

        def draw_branch(pad, inherited_from):
            for task, task_info in data.items():
                if task_info['inherited_from'] == inherited_from:
                    outfd.write("%s 0x%08X:%-20s %-6d %-6d %-6d %-6d %-26s\n" % (
                        "." * pad,
                        task_info['eprocess'].offset,
                        task_info['image_file_name'],
                        task_info['process_id'],
                        task_info['inherited_from'],
                        task_info['active_threads'],
                        task_info['handle_count'],
                        task_info['create_time']))

                    if config.VERBOSE > 1:
                        try:
                            outfd.write("%s    cmd: %s\n" % (
                                ' '*pad, task_info['command_line']))
                            outfd.write("%s    path: %s\n" % (
                                ' '*pad, task_info['ImagePathName']))
                            outfd.write("%s    audit: %s\n" % (
                                ' '*pad, task_info['Audit ImageFileName']) )
                        except KeyError:
                            pass
                        
                    draw_branch(pad + 1, task_info['process_id'])
                    del data[task]

        while len(data.keys())>0:
            keys = data.keys()
            root = self.find_root(data, keys[0])
            draw_branch(0, root)
        
    def calculate(self):
        result = {}
        
        ## Load a new address space
        addr_space = utils.load_as()
        addr_space.profile.add_types(pslist_types)

        for task in pslist(addr_space):
            task_info = {}
            task_info['eprocess'] = task
            task_info['image_file_name'] = task.ImageFileName or 'UNKNOWN'
            task_info['process_id']      = task.UniqueProcessId.v() or -1
            task_info['active_threads']  = task.ActiveThreads or -1
            task_info['inherited_from']  = task.InheritedFromUniqueProcessId.v() or -1
            task_info['handle_count']    = task.ObjectTable.HandleCount or -1
            task_info['create_time']     = task.CreateTime

            ## Get the Process Environment Block - Note that _EPROCESS
            ## will automatically switch to process address space by
            ## itself.
            if config.VERBOSE > 1:
                peb = task.Peb
                if peb:
                    task_info['command_line'] = peb.ProcessParameters.CommandLine
                    task_info['ImagePathName'] = peb.ProcessParameters.ImagePathName

                task_info['Audit ImageFileName'] = task.SeAuditProcessCreationInfo.ImageFileName.Name or 'UNKNOWN'
             
            result[task_info['process_id']] = task_info
            
        return result
