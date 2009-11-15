# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

import sys
import binascii
import xml.etree.cElementTree as etree
import volatility.commands as commands
import volatility.utils as utils
import volatility.conf as conf
config = conf.ConfObject()

PAGESIZE = 4096

#XML Example file format
#
#<patchfile>
#  <patchinfo method="pagescan">
#    <constraints>
#      <match offset="[offset within page]">DEADBEEFC0FFEE</match>
#      ...
#    </constraints>
#    <patch offset="[offset within page]">BEEFF00DEE</match>
#    ...
#  </patchinfo>
#</patchfile>

class MultiPageScanner(object):
    """Scans a page at a time through the address space
    
       Designed to minimize reads/writes to the address space
    """
    def __init__(self, full=True):
        self.constraints = {}
        self.maxlen = 0
        self.remove_patchers = not full
        self.patcher_set = set()
        
    def add_constraint(self, patcher, offset, data):
        """Adds a single constraint from a particular patch instance"""
        checklist = self.constraints.get(offset, [])
        checklist.append((patcher, data))
        # So we can tell when we have all the patchers
        self.patcher_set.add(patcher)
        # So we know the maximum we have to read
        self.maxlen = max(self.maxlen, len(data))
        self.constraints[offset] = checklist

    def scan(self, address_space, outfd):
        """Scans through the pages"""
        page_offset = 0

        while address_space.is_valid_address(page_offset + PAGESIZE):
            sys.stdout.write("\rScanning: {0:08X}".format(page_offset))
            # Keep a list so we can ignore checks in the future...
            failed_patchers = set()
            for offset in sorted(self.constraints.keys()):
                for patcher, data in self.constraints[offset]:
                    if patcher not in failed_patchers:
                        testdata = address_space.read(page_offset + offset, len(data))
                        if data != testdata:
                            failed_patchers.add(patcher)
                            
            # Run through any patchers that didn't fail
            for patcher in self.patcher_set:
                if patcher not in failed_patchers:
                    outfd.write("\rPatching {0} at page {1:x}\n".format(patcher.get_name(), page_offset))
                    patcher.patch(address_space, page_offset)
                    if self.remove_patchers:
                        self.patcher_set.remove(patcher)
                        self.remove_patcher(patcher)
            # Jump to the next page
            page_offset += PAGESIZE
        sys.stdout.write("\n")

    def remove_patcher(self, patcher):
        """Removes a patcher from the constraints structure"""
        for o in self.constraints:
            self.constraints[o] = [(p, d) for (p, d) in self.constraints[o] if p != patcher] 

class Patcher(object):
    """Simple object to hold patching data"""
    def __init__(self, name):
        self.patches = []
        self.name = name

    def add_patch(self, offset, patch):
        """Adds a patch to the patchlist"""
        # Ensure that all offsets are within PAGESIZE
        self.patches.append((offset % PAGESIZE, patch))
        
    def patch(self, addr_space, page_offset):
        """Writes to the address space"""
        result = True
        for offset, patch, in self.patches:
            result = result and addr_space.write(page_offset + offset, patch)
        return result

    def get_patches(self):
        """Returns the list of patches for this patcher"""
        return self.patches

    def get_name(self):
        """Returns the name of the patcher"""
        return self.name

class dllpatch(commands.command):
    """Patches DLLs based on page scans"""

    def __init__(self, *args, **kwargs):
        config.add_option('XML-INPUT', short_option='x',
                  help='Input XML file for patching binaries')
        
        commands.command.__init__(self, *args, **kwargs)        

    def calculate(self):
        """Calculates the patchers"""
        addr_space = utils.load_as(astype='physical')
        scanner = self.parse_patchfile()
        return scanner, addr_space
    
    def render_text(self, outfd, data):
        """Renders the text and carries out the patching"""
        scanner, addr_space = data
        scanner.scan(addr_space, outfd)

    def get_offset(self, tag):
        """Returns the offset from a tag"""
        offset = tag.get('offset', None)
        if not offset:
            return None
        base = 10
        if offset.startswith('0x'):
            offset = offset[2:]
            base = 16
        return int(offset, base)        

    def make_patcher(self, element, scanner):
        """Adds a patchinfo to the scanner object"""
        if not config.WRITE:
            config.error("The patcher plugin requires that write support be enabled")
        patcher = Patcher(element.get('name', 'Unlabelled'))
        constraints = None
        for tag in element:
            if tag.tag == 'constraints':
                constraints = tag
            if tag.tag == 'patches':
                patches = tag
        if constraints is None:
            config.error("Patch input file does not contain any valid constraints")

        # Parse the patches section
        for tag in patches:
            if tag.tag == 'setbytes':
                offset = self.get_offset(tag)
                data = binascii.a2b_hex(tag.text)
                if offset is not None and len(data):
                    patcher.add_patch(offset, data)
        if not len(patcher.get_patches()):
            # No patches, no point adding this
            return False
        
        # Parse the constraints section
        for c in constraints:
            if c.tag == 'match':
                offset = self.get_offset(c)
                data = binascii.a2b_hex(c.text)
                if offset is not None and len(data):
                    scanner.add_constraint(patcher, offset, data)
        return True

    def parse_patchfile(self):
        """Parses the patch XML data"""
        scanner = MultiPageScanner(True)
        if config.XML_INPUT is None:
            config.error("No XML input file was specified")
        try:
            root = etree.parse(config.XML_INPUT).getroot()
        except SyntaxError, e:
            config.error("XML input file was improperly formed: " + str(e))
        for patchinfo in root:
            if patchinfo.tag == 'patchinfo':
                if patchinfo.get('method', 'nomethod') == 'pagescan':
                    self.make_patcher(patchinfo, scanner)
                else:
                    config.error("Unsupported patchinfo method " + patchinfo.method)
        return scanner