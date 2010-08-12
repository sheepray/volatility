import volatility.conf as conf
config = conf.ConfObject()

import volatility.cache as cache
import pdb
import sys

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

Droping to a debugging shell....
"""
            pdb.set_trace()
            sys.exit(-1)
        else:
            print "\n\nTest Passed....\n"

def enable_unittestevents(_option, _opt_str, _value, _parser):
    """Enables the unit tests"""
        ## If this option was specified we force all nodes to be TestNodes
    print "Setting CacheNodes to TestNodes"
    cache.CACHE = cache.CacheTree(cache.CacheStorage(), cls = TestNode)

config.add_option("UNIT-TEST", default = None , action = 'callback',
                  callback = enable_unittestevents,
                  help = "Enable unit tests for this module")