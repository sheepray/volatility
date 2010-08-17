# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (C) 2009 Timothy D. Morgan (strings optimization)
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


import os
import volatility.commands as commands
import volatility.obj as obj
import volatility.utils as utils
import volatility.win32 as win32
import volatility.conf as conf
config = conf.ConfObject()

class strings(commands.command):
    """Match physical offsets to virtual addresses (may take a while, VERY verbose)"""

    def __init__(self, *args):
        config.add_option('STRING-FILE', short_option = 's', default = None,
                          help = 'File output in strings format (offset:string)',
                          action = 'store', type = 'str')
        config.add_option('PIDS', short_option = 'p', default = None,
                          help = 'Operate on these Process IDs (comma-separated)',
                          action = 'store', type = 'str')
        commands.command.__init__(self, *args)

    def calculate(self):
        """Calculates the physical to virtual address mapping"""
        if config.STRING_FILE is None or not os.path.exists(config.STRING_FILE):
            config.error("Strings file not found")

        data = {}

        addr_space = utils.load_as()

        tasks = win32.tasks.pslist(addr_space)

        try:
            if config.PIDS is not None:
                pidlist = [int(p) for p in config.PIDS.split(',')]
                tasks = [t for t in tasks if int(t.UniqueProcessId) in pidlist]
        except (ValueError, TypeError):
            # TODO: We should probably print a non-fatal warning here
            pass

        return addr_space, tasks

    def render_text(self, outfd, data):
        """Runs through the text file outputting which string appears where"""

        addr_space, tasks = data

        stringlist = open(config.STRING_FILE, "r")

        verbfd = None
        if config.VERBOSE:
            verbfd = outfd

        # Before we bother to start parsing the image, check to make sure the strings
        # are specified correctly
        parsedStrings = []
        for stringLine in stringlist:
            (offsetString, string) = self.parse_line(stringLine)
            try:
                offset = int(offsetString)
            except ValueError:
                config.error("String file format invalid.")
            parsedStrings.append((offset, string))

        reverse_map = self.get_reverse_map(addr_space, tasks, verbfd)

        for (offset, string) in parsedStrings:
            if reverse_map.has_key(offset & 0xFFFFF000):
                outfd.write("{0:08x} [".format(offset))
                outfd.write(' '.join(["{0}:{1}".format(pid[0], pid[1] | (offset & 0xFFF)) for pid in reverse_map[offset & 0xFFFFF000][1:]]))
                outfd.write("] {0}\n".format(string.strip()))

    def get_reverse_map(self, addr_space, tasks, verbfd = None):
        """Generates a reverse mapping from physical addresses to the kernel and/or tasks
        
           Returns:
           dict of form phys_page -> [isKernel, (pid1, vaddr1), (pid2, vaddr2) ...]
           where isKernel is True or False. if isKernel is true, list is of all kernel addresses
        """

        if verbfd is None:
            verbfd = obj.NoneObject("Swallow output unless VERBOSE mode is enabled")

        # ASSUMPTION: no pages mapped in kernel and userland
        # XXX: Can we eliminate the above assumption?  It seems like the only change needed for
        #      that would be to store a boolean with each pid/vaddr pair...
        #
        # XXX: The following code still fails to represent information about larger pages in
        #      the final output.  The output implies that addresses in a large page are
        #      really stored in one or more 4k pages.  This is no different from the old
        #      version of the code, but in this version it could be corrected easily by
        #      recording vpage instead of vpage+i in the reverse map. -- TDM
        reverse_map = {}

        verbfd.write("Calculating kernel mapping...\n")
        available_pages = addr_space.get_available_pages()
        for (vpage, vpage_size) in available_pages:
            kpage = addr_space.vtop(vpage)
            for i in range(0, vpage_size, 0x1000):
                # Since the output will always be mutable, we don't need to reinsert into the list
                pagelist = reverse_map.get(kpage + i, None)
                if pagelist is None:
                    pagelist = [True]
                    reverse_map[kpage + i] = pagelist
                pagelist.append(('kernel', vpage + i))
                verbfd.write("\r  Kernel [{0:08x}]".format(vpage))
        verbfd.write("\n")

        verbfd.write("Calculating task mappings...\n")
        for task in tasks:
            task_space = task.get_process_address_space()
            verbfd.write("  Task {0} ...".format(task.UniqueProcessId))
            process_id = int(task.UniqueProcessId)
            try:
                available_pages = task_space.get_available_pages()
                for (vpage, vpage_size) in available_pages:
                    physpage = task_space.vtop(vpage)
                    for i in range(0, vpage_size, 0x1000):
                        # Since the output will always be mutable, we don't need to reinsert into the list
                        pagelist = reverse_map.get(physpage + i, None)
                        if pagelist is None:
                            pagelist = [False]
                            reverse_map[physpage + i] = pagelist
                        if not pagelist[0]:
                            pagelist.append((process_id, vpage + i))

                    verbfd.write("\r  Task {0} [{1:08x}]".format(process_id, vpage))
            except (AttributeError, ValueError, TypeError):
                # Handle most errors, but not all of them
                continue
            verbfd.write("\n")
        verbfd.write("\n")
        return reverse_map

    def parse_line(self, stringLine):
        """Parses a line of strings"""
        # Remove any leading spaces to handle nasty strings output
        stringLine = stringLine.lstrip()
        maxlen = len(stringLine)
        split_char = ' '
        for char in [' ', ':']:
            charpos = stringLine.find(char)
            if charpos < maxlen and charpos > 0:
                split_char = char
                maxlen = charpos
        return tuple(stringLine.split(split_char, 1))
