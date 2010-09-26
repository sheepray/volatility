# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Derived from source in PyFlag developed by:
# Copyright 2004: Commonwealth of Australia.
# Michael Cohen <scudette@users.sourceforge.net> 
# David Collett <daveco@users.sourceforge.net>
#
# ******************************************************
#  Version: FLAG $Version: 0.84RC4 Date: Wed May 30 20:48:31 EST 2007$
# ******************************************************
#
# * This program is free software; you can redistribute it and/or
# * modify it under the terms of the GNU General Public License
# * as published by the Free Software Foundation; either version 2
# * of the License, or (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful,
# * but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# * GNU General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, write to the Free Software
# * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# *****************************************************

#pylint: disable-msg=C0111

""" This module implements a class registry.

We scan the memory_plugins directory for all python files and add those
classes which should be registered into their own lookup tables. These
are then ordered as required. The rest of Volatility will then call onto the
registered classes when needed.

This mechanism allows us to reorganise the code according to
functionality. For example we may include a Scanner, Report and File
classes in the same plugin and have them all automatically loaded.
"""

import os, sys, imp
import volatility.conf as conf
config = conf.ConfObject()
import volatility.debug as debug #pylint: disable-msg=W0611

config.add_option("INFO", default = None, action = "store_true",
                  cache_invalidator = False,
                  help = "Print information about all registered objects")

config.add_option("PLUGINS", default = "./plugins",
                  cache_invalidator = False,
                  help = "Additional plugin directories to use (colon separated)")


class ModuleRegistry(object):
    """A class to load and manage a set of python modules."""
    def __init__(self):
        self.namespaces = set()
        self.module_paths = []
        self.modules = {}
        self.get_modules()
        self.errors = {}

        ## The following code resolves dependencies by postponing
        ## loading of failed modules
        while 1:
            modules_left = len(self.module_paths)

            ## Try to compile some more
            self.module_paths = self.load_modules(self.module_paths)

            ## no change - we cant make any progress - report the
            ## failures and continue
            if modules_left == len(self.module_paths):
                for module_name, module_path in self.module_paths:
                    debug.debug("Unable to import {0}: {1}".format(module_name, self.errors[module_path]))

                break

    def get_module_objects(self):
        return self.modules.values()

    def load_modules(self, modules):
        """Load all the modules named in modules if possible.

        Returns:
          The modules which did not load.
        """

        results = []
        for module_name, module_path in modules:
            try:
                ## Temporarily load this module into a temporary
                ## name. It will be moved later to its desired
                ## namespace
                try:
                    del sys.modules['tmp_module']
                except KeyError:
                    pass

                module = imp.load_source("tmp_module", module_path)

                # The module name we use depends on the __namespace__ arg
                try:
                    module_name = "{0}.{1}".format(module.__namespace__, module_name)
                except AttributeError:
                    pass

                module.__name__ = module_name
                self.insert_module_to_system("volatility.plugins.%s" % module_name, module)

            except ImportError, e:
                results.append((module_name, module_path))
                self.errors[module_path] = e

        return results

    def insert_module_to_system(self, module_name, module):
        """Inserts the module into the sys.modules dict ensuring that
        intermediate modules are created.

        After this call modules can simply issue

        import module_name

        to receive the module.
        """
        ## We basically add the module to the module tree by ensure it
        ## has a continuous path to the root. If a node is missing we
        ## add a dummy node.
        self.modules[module_name] = sys.modules[module_name] = module

        ## Now check that its reachable
        module_path = module_name.split(".")
        for i in range(len(module_path) - 1, 0, -1):
            component = ".".join(module_path[0:i])
            try:
                setattr(sys.modules[component], module_path[i], module)
                ## We have reached a connected node - we just need to
                ## set a new property and quit (We assume that if its
                ## already in the tree its connected to the root).
                break

            except KeyError:
                sys.modules[component] = imp.new_module(component)

                setattr(sys.modules[component], module_path[i], module)

                module = sys.modules[component]

    def get_modules(self):
        """Iterates over all the plugin paths to discover modules.

        Returns:
           a dict of potential modules and paths.
        """
        # Setup initial plugin directories
        plugins = config.PLUGINS

        ## Recurse over all the plugin directories recursively
        for path in plugins.split(';'):
            # FIXME: Windows Absolute Paths don't start with /
            if path.startswith('/'):
                path = os.path.abspath(path)
            else:
                # Take the executable path
                relbase = sys.argv[0]
                if hasattr(sys, "frozen") or hasattr(sys, "importers") or imp.is_frozen("__main__"):
                    # Use the actual executable path if the script's frozen (running within py2exe)
                    relbase = sys.executable
                path = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(relbase)), path))

            for dirpath, _dirnames, filenames in os.walk(path):
                for filename in filenames:
                    #Lose the extension for the module name
                    module_name = filename[:-3]
                    if filename.endswith(".py"):
                        path = os.path.join(dirpath, filename)
                        self.module_paths.append((module_name, path))


class MemoryRegistry(object):
    """ Main class to register classes derived from a given parent
    class. 
    """
    ## NOTE - These are class attributes - they will be the same for
    ## all classes, subclasses and future instances of them. They DO
    ## NOT get reset for each instance.
    modules = []
    module_desc = []
    module_paths = []

    def __init__(self, ParentClass, modules):
        """ Search the plugins directory for all classes extending
        ParentClass.

        These will be considered as implementations and added to our
        internal registry.  
        """
        ## Create instance variables
        self.classes = []
        self.class_names = []
        self.order = []
        self.ParentClass = ParentClass

        for module in modules.get_module_objects():
            self.load_module(module)

    def load_module(self, module):
        """Grabs all the classes inheriting from self.ParentClass in
        the module object.
        """
        #Now we enumerate all the classes in the
        #module to see which one is a ParentClass:

        for cls in dir(module):
            try:
                Class = module.__dict__[cls]
                if issubclass(Class, self.ParentClass) and Class != self.ParentClass:
                    ## Check the class for consistency
                    try:
                        self.check_class(Class)
                    except AttributeError, e:
                        print "Failed to load {0} '{1}': {2}".format(self.ParentClass, cls, e)
                        continue

                    ## Add the class to ourselves:
                    self.add_class(Class)

            # Oops: it isnt a class...
            except (TypeError, NameError) , e:
                continue

    def add_class(self, Class):
        """ Adds the class provided to our self. This is here to be
        possibly over ridden by derived classes.
        """
        if Class not in self.classes:
            self.classes.append(Class)
            try:
                self.order.append(Class.order)
            except AttributeError:
                self.order.append(10)

    def check_class(self, Class):
        """ Run a set of tests on the class to ensure its ok to use.

        If there is any problem, we chuck an exception.
        """
        if Class.__name__.lower().startswith("abstract"):
            raise NotImplemented("This class is an abstract class")

    def get_name(self, cls):
        try:
            return cls.name
        except AttributeError:
            return ("{0}".format(cls)).split(".")[-1]

class VolatilityCommandRegistry(MemoryRegistry):
    """ A class to manage commands """
    def __getitem__(self, command_name):
        """ Return the command objects by name """
        return self.commands[command_name]

    def __init__(self, ParentClass, modules):
        MemoryRegistry.__init__(self, ParentClass, modules)
        self.commands = {}

        for cls in self.classes:
            ## The name of the class is the command name
            command = cls.__name__.split('.')[-1].lower()
            try:
                raise Exception("Command {0} has already been defined by {1}".format(command, self.commands[command]))
            except KeyError:
                self.commands[command] = cls

class VolatilityObjectRegistry(MemoryRegistry):
    """ A class to manage objects """
    def __getitem__(self, object_name):
        """ Return the objects by name """
        return self.objects[object_name]

    def __init__(self, ParentClass, modules):
        MemoryRegistry.__init__(self, ParentClass, modules)
        self.objects = {}

        ## First we sort the classes according to their order
        def sort_function(x, y):
            try:
                a = x.order
            except AttributeError:
                a = 10

            try:
                b = y.order
            except AttributeError:
                b = 10

            if a < b:
                return - 1
            elif a == b:
                return 0
            return 1

        self.classes.sort(sort_function)

        for cls in self.classes:
            ## The name of the class is the object name
            obj = cls.__name__.split('.')[-1]
            try:
                raise Exception("Object {0} has already been defined by {1}".format(obj, self.objects[obj]))
            except KeyError:
                self.objects[obj] = cls

def print_info():
    for k, v in globals().items():
        if isinstance(v, MemoryRegistry):
            print "\n"
            print "{0}".format(k)
            print "-" * len(k)

            result = []
            max_length = 0
            for cls in v.classes:
                try:
                    doc = cls.__doc__.strip().splitlines()[0]
                except AttributeError:
                    doc = 'No docs'
                result.append((cls.__name__, doc))
                max_length = max(len(cls.__name__), max_length)

            ## Sort the result
            result.sort(key = lambda x: x[0])

            for x in result:
                print "{0:{2}} - {1:15}".format(x[0], x[1], max_length)

LOCK = 0
PLUGIN_COMMANDS = None
OBJECT_CLASSES = None
AS_CLASSES = None
PROFILES = None
SCANNER_CHECKS = None

## This is required for late initialization to avoid dependency nightmare.
def Init():
    ## Load all the modules:
    modules = ModuleRegistry()

    ## LOCK will ensure that we only initialize once.
    global LOCK
    if LOCK:
        return
    LOCK = 1

    ## Register all shell commands:
    import volatility.commands as commands
    global PLUGIN_COMMANDS
    PLUGIN_COMMANDS = VolatilityCommandRegistry(commands.command, modules)

    import volatility.addrspace as addrspace
    global AS_CLASSES
    AS_CLASSES = VolatilityObjectRegistry(addrspace.BaseAddressSpace, modules)

    global PROFILES
    import volatility.obj as obj
    PROFILES = VolatilityObjectRegistry(obj.Profile, modules)

    import volatility.scan as scan
    global SCANNER_CHECKS
    SCANNER_CHECKS = VolatilityObjectRegistry(scan.ScannerCheck, modules)

    if config.INFO:
        print_info()
        sys.exit(0)
