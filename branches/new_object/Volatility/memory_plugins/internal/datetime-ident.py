'''
Created on 20 Sep 2009

@author: Mike Auty
'''

import forensics.object2 as object2
import forensics.win32 as win32
import forensics.utils as utils
import forensics.commands
import vmodules

#pylint: disable-msg=C0111

class datetime(forensics.commands.command):

    def __init__(self, args=None):
        forensics.commands.command.__init__(self, args)
        self.profile = None

    def render_text(self, outfd, data):
        """Renders the calculated data as text to outfd"""
        outfd.write("Image local date and time: %s\n" % data['ImageDatetime'])

    def calculate(self):
        result = {}
        self.profile = object2.Profile()

        addr_space = utils.load_as()
        
        # Get the Image Datetime
        result['ImageDatetime'] = self.get_image_datetime(addr_space)

        return result

    def get_image_datetime(self, addr_space):
        """Returns the image datetime"""
        k = object2.NewObject("_KUSER_SHARED_DATA", win32.info.KUSER_SHARED_DATA, addr_space, profile=self.profile)
        return k.SystemTime - k.TimeZoneBias

class ident(datetime):
    """ Identify information for the image """
    def __init__(self, args=None):
        datetime.__init__(self, args)
    
    def render_text(self, outfd, data):
        """Renders the calculated data as text to outfd"""
        outfd.write("              Image Name: %s\n" % data['ImageName'])
        outfd.write("              Image Type: %s\n" % data['ImageType'])
        outfd.write("                 VM Type: %s\n" % data['ImagePAE'])
        outfd.write("                     DTB: %s\n" % data['ImageDTB'])
        outfd.write("                Datetime: %s\n" % data['ImageDatetime'])
    
    def calculate(self):
        result = {}
        addr_space = utils.load_as()

        # Get the name
        tmpspace = addr_space
        result['ImageName'] = 'Unknown'
        while tmpspace is not None:
            if hasattr(tmpspace, 'name'):
                result['ImageName'] = tmpspace.name
            tmpspace = tmpspace.base

        # Get the Image Type
        result['ImageType'] = self.find_csdversion(addr_space)
        
        # Get the VM Type
        result['ImagePAE'] = 'nopae'
        if addr_space.pae:
            result['ImagePAE'] = 'pae'
        
        # Get the Image DTB
        result['ImageDTB'] = hex(addr_space.load_dtb())
        
        # Get the Image Datetime
        result['ImageDatetime'] = self.get_image_datetime(addr_space)

        return result

    def find_csdversion(self, addr_space):
        """Find the CDS version from an address space"""
        csdvers = {}
        for task in win32.tasks.pslist(addr_space, self.profile):
            if task.Peb.CSDVersion:
                lookup = str(task.Peb.CSDVersion)
                csdvers[lookup] = csdvers.get(lookup, 0) + 1
                _, result = max([(v, k) for k, v in csdvers.items()])
                
                return str(result)
            
        return object2.NoneObject("Unable to find version")
