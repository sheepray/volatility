import volatility.commands as commands
import volatility.conf as conf
config = conf.ConfObject()

import volatility.cache as cache
import pdb
import sys
import volatility.debug as debug

class TestNode(cache.CacheNode):
    """ A CacheNode for implementing unit tests """
    def __getitem__(self, item):
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

Test: %s
Previous Value: %s
Current Value: %s

Droping to a debugging shell....
""" % (self.stem, original_result.payload, self.payload)
            pdb.set_trace()
            sys.exit(-1)
        else:
            print "\n\nTest Passed....\n"

class UnitTestEvents(commands.EventHandler):
    def XXXstartup(self):
        ## If this option was specified we force all nodes to be TestNodes
        if config.UNIT_TEST:
            print "Setting CacheNodes to TestNodes"
            cache.CACHE = cache.CacheTree(cache.CacheStorage(), cls = TestNode)

import volatility.registry as MemoryRegistry

class TestSuits(commands.command):
  """ Run unit test suit using the Cache """
  def __init__(self, *args):
    config.add_option("UNIT-TEST", default=False , action = 'store_true',
                      help = "Enable unit tests for this module")

    config.add_option("MODULES", default='',
                      help = "Only test these comma delimited set of modules")

    commands.command.__init__(self, *args)

  def execute(self):
    if config.UNIT_TEST:
        print "Setting CacheNodes to TestNodes"
        cache.CACHE = cache.CacheTree(cache.CacheStorage(), cls = TestNode)


    commands = MemoryRegistry.PLUGIN_COMMANDS.commands
    modules = config.MODULES.split(",")

    for cmdname in commands:
      if modules and cmdname not in modules: continue

      try:
        command = MemoryRegistry.PLUGIN_COMMANDS[cmdname]()
        if isinstance(command, cache.Testable):
          print "Executing %s" % cmdname
          command.test()

      except Exception,e:
        print "Error running %s - %s" % (cmdname, e)
        debug.post_mortem()

class InspectCache(commands.command):
  """ Inspect the contents of a cache """
  def __init__(self, *args):
    config.add_option("CACHE-LOCATION", default=None,
                      help = "Location of the cache element")
    commands.command.__init__(self, *args)

  def execute(self):
    node = cache.CACHE[config.CACHE_LOCATION]

    ## FIXME - nicer pretty printing here
    print node.payload
