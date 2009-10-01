'''
Created on 30 Sep 2009

@author: Mike Auty
'''

import forensics.utils as utils
import forensics.win32 as win32
import forensics.object2 as object2
import forensics.commands as commands
import forensics.conf

config = forensics.conf.ConfObject()

config.add_option('OFFSET', short_option = 'o', default=None,
    help='EPROCESS Offset (in hex) in physical address space',
    action='store', type='string')

config.add_option('PID', short_option = 'p',
    help='Get info for this Pid', default=None,
    action='store', type='int')

class vadinfo(commands.command):
    """Dump the VAD info"""

    def render_text(self, outfd, data):
        for pid in data:
            outfd.write("*" * 72 + "\n")
            outfd.write("Pid: %-6d\n" % (pid))
            for vad in data[pid]['vadlist']:
                if vad is None:
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
                    else:
                        vadlist.append(None)
                
                result[pid]['vadlist'] = vadlist
                    
        return result
    
    def accumulate_vads(self, root):
        """Traverses the Vad Tree based on Left and Right children"""
        leftside = []
        rightside = []
        if root.LeftChild:
            leftside = self.accumulate_vads(root.LeftChild.dereference())
        if root.RightChild:
            rightside = self.accumulate_vads(root.RightChild.dereference())
        return [root] + leftside + rightside