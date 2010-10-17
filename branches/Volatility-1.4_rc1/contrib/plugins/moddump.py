# Volatility
# Copyright (C) 2007,2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
#
# Additional Authors:
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

import os
import re
import volatility.plugins.procdump as procdump
import volatility.win32.modules as modules
import volatility.utils as utils
import volatility.debug as debug
import volatility.conf as conf
config = conf.ConfObject()

class ModDump(procdump.ProcExeDump):
    """Dump a kernel driver to an executable file sample"""

    def __init__(self, *args):
        procdump.ProcExeDump.__init__(self, *args)
        config.remove_option("PID")
        config.remove_option("OFFSET")
        config.add_option('REGEX', short_option = 'r',
                      help = 'Dump modules matching REGEX',
                      action = 'store', type = 'string', dest = 'regex')
        config.add_option('IGNORE-CASE', short_option = 'i',
                      help = 'Ignore case in pattern match',
                      action = 'store_true', default = False, dest = 'ignore_case')
        config.add_option('OFFSET', short_option = 'o', default = None,
                          help = 'Dump driver with base address OFFSET (in hex)',
                          action = 'store', type = 'int')

    def calculate(self):
        addr_space = utils.load_as()

        if config.DUMP_DIR == None:
            debug.error("Please specify a dump directory (--dump-dir)")
        if not os.path.isdir(config.DUMP_DIR):
            debug.error(config.DUMP_DIR + " is not a directory")

        if config.regex:
            try:
                if config.ignore_case:
                    mod_re = re.compile(config.regex, re.I)
                else:
                    mod_re = re.compile(config.regex)
            except re.error, e:
                debug.error('Error parsing regular expression: %s' % e)

        mods = dict((mod.DllBase.v(), mod) for mod in modules.lsmod(addr_space))

        if config.offset:
            if mods.has_key(config.offset):
                yield addr_space, mods[config.offset]
            else:
                raise StopIteration('No such module at 0x{0:X}'.format(config.offset))
        else:
            for mod in mods.values():
                if config.regex:
                    if not mod_re.search(str(mod.FullDllName)) and not mod_re.search(str(mod.BaseDllName)):
                        continue
                yield addr_space, mod

    def render_text(self, outfd, data):
        for addr_space, mod in data:
            if addr_space.is_valid_address(mod.DllBase):
                dump_file = "driver.{0:x}.sys".format(mod.DllBase)
                outfd.write("Dumping {0}, Base: {1:8x} output: {2}\n".format(mod.BaseDllName, mod.DllBase, dump_file))
                of = open(os.path.join(config.DUMP_DIR, dump_file), 'wb')
                try:
                    for chunk in self.get_image(outfd, addr_space, mod.DllBase):
                        offset, code = chunk
                        of.seek(offset)
                        of.write(code)
                except ValueError, ve:
                    outfd.write("Unable to dump executable; sanity check failed:\n")
                    outfd.write("  " + str(ve) + "\n")
                    outfd.write("You can use -u to disable this check.\n")
                of.close()
            else:
                print 'Cannot dump {0} at {1:8x}'.format(mod.BaseDllName, mod.DllBase)
