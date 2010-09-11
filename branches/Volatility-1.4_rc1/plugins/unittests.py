# Volatility
# 
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
@author:       Michael Cohen
@license:      GNU General Public License 2.0 or later
@contact:      scudette@users.sourceforge.net
"""

import pdb
import sys
import volatility.registry as MemoryRegistry
import volatility.commands as commands
import volatility.debug as debug
import volatility.cache as cache
import volatility.conf as conf
config = conf.ConfObject()

class TestNode(cache.CacheNode):
    """ A CacheNode for implementing unit tests """
    def __getitem__(self, item = ''):
        raise KeyError("Cache miss forced for unit tests")

    def dump(self):
        original_result = cache.CacheNode.__getitem__(self, '')

        ## See if the results are lists:
        try:
            ## We convert it to sets here to ensure the comparison is
            ## order independent:
            result = set(original_result.payload) == set(self.payload)
        except TypeError:
            result = original_result.payload == self.payload

        if not result:
            print """ERROR - cached version is not reproduceable.... There must be a regression bug here!!!

Test: {0}
Previous Value: {1}
Current Value: {2}

Droping to a debugging shell....
""".format(self.stem, original_result.payload, self.payload)
            pdb.set_trace()
            sys.exit(-1)
        else:
            print "\n\nTest Passed....\n"

class TestSuite(commands.command):
    """ Run unit test suit using the Cache """
    def __init__(self, *args):
        config.add_option("UNIT-TEST", default = False , action = 'store_true',
                          help = "Enable unit tests for this module")

        config.add_option("MODULES", default = '',
                          help = "Only test these comma delimited set of modules")

        commands.command.__init__(self, *args)

    def execute(self):
        if config.UNIT_TEST:
            print "Setting CacheNodes to TestNodes"
            cache.CACHE = cache.CacheTree(cache.CacheStorage(), cls = TestNode, invalidator = cache.CACHE.invalidator)

        cmds = MemoryRegistry.PLUGIN_COMMANDS.commands
        modules = None
        if config.MODULES:
            modules = config.MODULES.split(",")

        for cmdname in cmds:
            if modules and cmdname not in modules:
                continue

            try:
                command = MemoryRegistry.PLUGIN_COMMANDS[cmdname]()
                if isinstance(command, cache.Testable):
                    print "Executing {0}".format(cmdname)
                    command.test()

            except Exception, e:
                print "Error running {0} - {1}".format(cmdname, e)
                debug.post_mortem()

class InspectCache(commands.command):
    """ Inspect the contents of a cache """
    def __init__(self, *args):
        config.add_option("CACHE-LOCATION", default = None,
                          help = "Location of the cache element")
        commands.command.__init__(self, *args)

    def execute(self):
        node = cache.CACHE[config.CACHE_LOCATION]

        ## FIXME - nicer pretty printing here
        print repr(node.get_payload())
