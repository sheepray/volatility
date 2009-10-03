#!/usr/bin/python
#  -*- mode: python; -*-
#
# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import sys, textwrap
import forensics.registry as MemoryRegistry
import forensics.conf
config = forensics.conf.ConfObject()
from forensics.object2 import Curry

config.add_option('DEBUG', short_option = 'd', action='count',
                  help = 'Debug volatility', default=0)

from vmodules import *

modules = {
    'pslist':
    VolatoolsModule('pslist',
                    'Print list of running processes',
                    get_pslist),
    'strings':
    VolatoolsModule('strings',
                    'Match physical offsets to virtual addresses (may take a while, VERY verbose)',
                    get_strings),
    'vaddump':
            VolatoolsModule('vaddump',
		    'Dump the Vad sections to files',
		    vaddump),
    'psscan':
            VolatoolsModule('psscan',
		    'Scan for EPROCESS objects',
		    psscan),
    'thrdscan':
            VolatoolsModule('thrdscan',
		    'Scan for ETHREAD objects',
     		    thrdscan),
    'sockscan':
            VolatoolsModule('sockscan',
		    'Scan for socket objects',
		    sockscan),
    'connscan':
            VolatoolsModule('connscan',
		    'Scan for connection objects',
		    connscan),
    'modscan':
    VolatoolsModule('modscan',
            'Scan for modules',
            modscan), 
    'memdmp':
    VolatoolsModule('memdmp',
            'Dump the addressable memory for a process',
            mem_dump), 
    'raw2dmp':
        VolatoolsModule('raw2dmp',
                    'Convert a raw dump to a crash dump',
                    raw2dmp),
    'dmp2raw':
        VolatoolsModule('dmp2raw',
                    'Convert a crash dump to a raw dump',
                    dmp2raw),
    'regobjkeys':
    VolatoolsModule('regkeys',
                  'Print list of open regkeys for each process',
                  get_open_keys),
    'procdump':
    VolatoolsModule('procdump',
                  'Dump a process to an executable sample',
                  procdump),
    'psscan2':
    VolatoolsModule('psscan2',
                  'Scan for process objects (New)',
                  psscan2),
    'hibinfo':
    VolatoolsModule('hibinfo',
            'Convert hibernation file to linear raw image',
            hibinfo), 
    }


def list_modules():
    result = "\n\tSupported Internel Commands:\n\n"
    keys = modules.keys()
    keys.sort()
    for mod in keys:
        result += "\t\t%-15s\t%-s\n" % (mod, modules[mod].desc())
        
    return result

def list_plugins():
    result = "\n\tSupported Plugin Commands:\n\n"
    keys = MemoryRegistry.PLUGIN_COMMANDS.commands.keys()
    keys.sort()
    for cmdname in keys:
        command = MemoryRegistry.PLUGIN_COMMANDS[cmdname]()
        help = command.help()
        ## Just put the title line (First non empty line) in this
        ## abbreviated display
        try:
            for line in help.splitlines():
                if line:
                    help = line
                    break
        except:
            help = ''
        result += "\t\t%-15s\t%-s\n" % (cmdname, help)

    return result

def usage(progname):
    print ""
    print "\tCopyright (C) 2007,2008 Volatile Systems"
    print "\tCopyright (C) 2007 Komoku, Inc."
    print "\tThis is free software; see the source for copying conditions."
    print "\tThere is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
    print ""
    print "\tusage: %s cmd [cmd_opts]\n" % (progname)
    print "\tRun command cmd with options cmd_opts"
    print "\tFor help on a specific command, run '%s cmd --help'" % (progname)
    print
    list_modules()
    print
    list_plugins()
    print
    print "\tExample: volatility pslist -f /path/to/my/file"
    sys.exit(0)

def command_help(command):
    result = textwrap.dedent("""
    ---------------------------------
    Module %s
    ---------------------------------\n""" % command.__class__.__name__)
    
    return result + command.help()

def main():

    # Get the version information on every output from the beginning
    # Exceptionally useful for debugging/telling people what's going on
    print "Volatile Systems Volatility Framework " + forensics.version

    MemoryRegistry.Init()

    ## Parse all the options now
    config.parse_options(False)
    try:
        module = config.args[0]
    except IndexError:
        config.parse_options()
        config.error("You must specify something to do (try -h)")
        
    if module not in modules and \
           module not in MemoryRegistry.PLUGIN_COMMANDS.commands:
        config.parse_options()        
        config.error("Invalid module [%s]." % (module))

    try:
        if module in modules:
            command = modules[module]
            config.set_help_hook(Curry(command_help, command))
            config.parse_options()
            
            command.execute(module, config.args[1:])
            
        elif module in MemoryRegistry.PLUGIN_COMMANDS.commands:
            command = MemoryRegistry.PLUGIN_COMMANDS[module](config.args[1:])

            ## Register the help cb from the command itself
            config.set_help_hook(Curry(command_help, command))
            config.parse_options()
             
            command.execute()
    except forensics.utils.AddrSpaceError, e:
        print e

if __name__ == "__main__":
    config.set_usage(usage = "Volatility - A memory forensics analysis platform.")
    config.add_help_hook(list_modules)
    config.add_help_hook(list_plugins)
    
    try:
        main()
    except Exception, ex:
        print ex
        if config.DEBUG:
            import pdb
            pdb.post_mortem()

