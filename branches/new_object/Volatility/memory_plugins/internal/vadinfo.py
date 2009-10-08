'''
Created on 30 Sep 2009

@author: Mike Auty
'''

import os.path
import forensics.win32 as win32
import forensics.object2 as object2
import forensics.conf
import taskmods

config = forensics.conf.ConfObject()

# Inherit from dlllist just for the config options (__init__)
class vadinfo(taskmods.dlllist):
    """Dump the VAD info"""

    def render_text(self, outfd, data):
        
        for pid in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: %-6d\n" % (pid))
            for vad in data[pid]['vadlist']:
                if vad == None:
                    outfd.write("Error: Unknown Tag")
                else:
                    self.write_vad_short(outfd, vad)
                    if vad.name != 'VadS':
                        self.write_vad_control(outfd, vad)
                        self.write_vad_ext(outfd, vad)
                outfd.write("\n")

    def write_vad_short(self, outfd, vad):
        """Renders a text version of a Short Vad"""
        outfd.write("VAD node @%08x Start %08x End %08x Tag %4s\n" % (vad.offset, int(vad.StartingVpn) << 12, ((int(vad.EndingVpn) + 1) << 12) - 1, vad.name))
        Flags = int(vad.Flags)
        outfd.write("Flags: " + ", ".join(win32.vad.get_bit_flags(Flags,'_MMVAD_FLAGS')) + "\n")
        outfd.write("Commit Charge: %d Protection: %x\n" % (Flags & win32.vad.get_mask_flag('_MMVAD_FLAGS', 'CommitCharge'), (Flags & win32.vad.get_mask_flag('_MMVAD_FLAGS', 'Protection')) >> 24))
    
    def write_vad_control(self, outfd, vad):
        """Renders a text version of a (non-short) Vad's control information"""
        CA = vad.ControlArea
        if not CA:
            return

        outfd.write("ControlArea @%08x Segment %08x\n" % (CA.dereference().offset, CA.Segment))
        outfd.write("Dereference list: Flink %08x, Blink %08x\n" % (CA.DereferenceList.Flink, CA.DereferenceList.Blink))
        outfd.write("NumberOfSectionReferences: %10d NumberOfPfnReferences:  %10d\n" % (CA.NumberOfSectionReferences, CA.NumberOfPfnReferences))
        outfd.write("NumberOfMappedViews:       %10d NumberOfSubsections:    %10d\n" % (CA.NumberOfMappedViews, CA.NumberOfSubsections))
        outfd.write("FlushInProgressCount:      %10d NumberOfUserReferences: %10d\n" % (CA.FlushInProgressCount, CA.NumberOfUserReferences))
        
        Flags = int(CA.Flags)
        outfd.write("Flags: " + ", ".join(win32.vad.get_bit_flags(Flags,'_MMSECTION_FLAGS')) + "\n")

        if CA.FilePointer:
            outfd.write("FileObject @%08x           , Name: %s\n" % (CA.FilePointer.dereference().offset, CA.FilePointer.FileName))
        else:
            outfd.write("FileObject: none\n")

        outfd.write("WaitingForDeletion Event: %08x\n" % CA.WaitingForDeletion)
        outfd.write("ModifiedWriteCount: %8d NumberOfSystemCacheViews: %8d\n" % (CA.ModifiedWriteCount, CA.NumberOfSystemCacheViews))
    
    def write_vad_ext(self, outfd, vad):
        """Renders a text version of a Long Vad"""
        outfd.write("First prototype PTE: %08x Last contiguous PTE: %08x\n" % (vad.FirstPrototypePte, vad.LastContiguousPte))
        
        Flags = int(vad.Flags2) 
        outfd.write("Flags2: " + ", ".join(win32.vad.get_bit_flags(Flags,'_MMVAD_FLAGS2')) + "\n")
        outfd.write("File offset: %08x\n" % (Flags & win32.vad.get_mask_flag('_MMVAD_FLAGS2','FileOffset')))
        
        if (Flags and Flags & win32.vad.get_mask_flag('_MMVAD_FLAGS2','LongVad')):
            # FIXME: Add in the extra bits, after deciding on names for u3 and u4
            outfd.write("Extended information available\n")

    def calculate(self):
        result = {}
        tasks = taskmods.dlllist.calculate(self)
        
        for task in tasks:
            if task.UniqueProcessId:
                pid = int(task.UniqueProcessId)
                if config.PID and pid != config.PID:
                    continue
                
                result[pid] = {'task': task, 'vadlist': []}

                task_space = task.get_process_address_space()

                vadroot = object2.NewObject("_MMVAD_SHORT", task.VadRoot, task_space)
                vadlist = []
                for vad in self.accumulate_vads(vadroot):
                    # We're going to abuse the name field to store the tag because whilst it should be a part of the structure
                    # it appears before the pointer's address (ie, the start of the structure)
                    vadtype = str(object2.NativeType("Bytes", vad.offset - 4, task_space, format_string = "4s"))
                    if vadtype == 'Vadl':
                        vadlist.append(object2.NewObject("_MMVAD_LONG", vad.offset, task_space, name="Vadl"))
                    elif vadtype == 'VadS':
                        vadlist.append(object2.NewObject("_MMVAD_SHORT", vad.offset, task_space, name="VadS"))
                    elif vadtype == 'Vad ':
                        vad.name = 'Vad '
                        vadlist.append(vad)
                    elif vadtype == 'VadF':
                        # TODO: Figure out what a VadF looks like!
                        vad.name = 'VadF'
                        vadlist.append(object2.NewObject("_MMVAD_SHORT", vad.offset, task_space, name="VadF"))
                    else:
                        # print "Vad with tag:", vadtype
                        vadlist.append(None)
                
                result[pid]['vadlist'] = vadlist
                    
        return sorted(result)
    
    def accumulate_vads(self, root):
        """Traverses the Vad Tree based on Left and Right children"""
        leftside = []
        rightside = []
        if root.LeftChild:
            leftside = self.accumulate_vads(root.LeftChild.dereference())
        if root.RightChild:
            rightside = self.accumulate_vads(root.RightChild.dereference())
        return [root] + leftside + rightside
    
class vadtree(vadinfo):
    """Walk the VAD tree and display in tree format"""
    
    def render_text(self, outfd, data):
        for pid in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: %-6d\n" % (pid))
            levels = {}
            for vad in data[pid]['vadlist']:
                # Ignore Vads with bad tags (which we explicitly include as None)
                if vad != None:
                    level = levels.get(vad.Parent.dereference().offset, -1) + 1
                    levels[vad.offset] = level
                    outfd.write(" " * level + "%08x - %08x\n" % ( 
                                int(vad.StartingVpn) << 12,
                                ((int(vad.EndingVpn) + 1) << 12) -1))

    def render_dot(self, outfd, data):
        for pid in data:
            outfd.write("/" + "*" * 72 + "/\n")
            outfd.write("/* Pid: %-6d */\n" % (pid))
            outfd.write("digraph processtree {\n")
            outfd.write("graph [rankdir = \"TB\"];\n")
            for vad in data[pid]['vadlist']:
                # Ignore Vads with bad tags (which we explicitly include as None)
                if vad != None:
                    if vad.Parent:
                        outfd.write("vad_%08x -> vad_%08x\n" % (vad.Parent.dereference().offset, vad.offset))                    
                    outfd.write("vad_%08x [label = \"{ %s\\n%08x - %08x }\" shape = \"record\" color = \"blue\"];\n" % 
                                (vad.offset,
                                 vad.name, 
                                 int(vad.StartingVpn) << 12,
                                 ((int(vad.EndingVpn) + 1) << 12) -1))
            outfd.write("}\n")

class vadwalk(vadinfo):
    """Walk the VAD tree"""
    
    def render_text(self, outfd, data):
        for pid in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: %-6d\n" % (pid))
            outfd.write("Address  Parent   Left     Right    Start    End      Tag  Flags\n")
            for vad in data[pid]['vadlist']:
                # Ignore Vads with bad tags (which we explicitly include as None)
                if vad != None:
                    outfd.write("%08x %08x %08x %08x %08x %08x %-4s\n" % (vad.offset,
                                vad.Parent.dereference().offset or 0 , vad.LeftChild.dereference().offset or 0,
                                vad.RightChild.dereference().offset or 0,
                                int(vad.StartingVpn) << 12,
                                ((int(vad.EndingVpn) + 1) << 12) -1,
                                vad.name))

class vaddump2(vadinfo):
    """Dumps out the vad sections to a file"""

    def __init__(self, *args):
        config.add_option('DUMP_DIR', short_option='D', default=None,
                          help='Directory in which to dump the VAD files')
        config.add_option('VERBOSE', short_option='v', default=False, type='bool',
                          help='Print verbose progress information')
        vadinfo.__init__(self, *args)

    def render_text(self, outfd, data):
        if config.DUMP_DIR == None:
            config.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(config.DUMP_DIR):
            config.error(config.DUMP_DIR + " is not a directory")

        for pid in data:
            print "Pid", pid
            # Get the task and all process specific information
            task = data[pid].get('task', None)
            task_space = task.get_process_address_space()
            name = task.ImageFileName
            offset = task_space.vtop(task.offset)

            outfd.write("*" * 72 + "\n")
            for vad in data[pid]['vadlist']:
                # Ignore Vads with bad tags (which we explicitly include as None)
                if vad == None:
                    continue

                # Find the start and end range
                start = int(vad.StartingVpn) << 12
                end = ((int(vad.EndingVpn) + 1) << 12) - 1
                if start > 0xFFFFFFFF or end > (0xFFFFFFFF << 12):
                    continue

                # Open the file and initialize the data
                f = open(os.path.join(config.DUMP_DIR, "%s.%x.%08x-%08x.dmp" % (name, offset, start, end)), 'wb')
                range_data = ""
                num_pages = (end - start + 1) >> 12

                for i in range(0, num_pages):
                    # Run through the pages gathering the data
                    page_addr = start + (i * 0x1000)
                    if not task_space.is_valid_address(page_addr):
                        range_data += ('\0' * 0x1000)
                        continue
                    page_read = task_space.read(page_addr, 0x1000)
                    if page_read == None:
                        range_data = range_data + ('\0' * 0x1000)
                    else:
                        range_data = range_data + page_read

                if config.VERBOSE:
                    outfd.write("Writing VAD for " + ("%s.%x.%08x-%08x.dmp" % (name, offset, start, end)) + "\n")
                f.write(range_data)
                f.close()