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

class MemoryRegistry:
    """ Main class to register classes derived from a given parent
    class. 
    """
    ## NOTE - These are class attributes - they will be the same for
    ## all classes, subclasses and future instances of them. They DO
    ## NOT get reset for each instance.
    modules = []
    module_desc = []
    module_paths = []
    filenames = {}

    def __init__(self, ParentClass):
        """ Search the plugins directory for all classes extending
        ParentClass.

        These will be considered as implementations and added to our
        internal registry.  
        """

        ## Create instance variables
        self.classes = []
        self.class_names = []
        self.order = []

        # Setup initial plugin directories
        plugins = config.PLUGINS

        ## Recurse over all the plugin directories recursively
        for path in plugins.split(':'):
            # Given it's a colon separated list, currently providing absolute paths on windows are impossible
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
                sys.path.append(dirpath)

                for filename in filenames:
                    #Lose the extension for the module name
                    module_name = filename[:-3]
                    if filename.endswith(".py"):
                        path = os.path.join(dirpath, filename)
                        try:
                            if path not in self.module_paths:
                                ## If we do not have the module in the 
                                ## cache, we load it now
                                try:
                                    #open the plugin file
                                    fd = open(path, "r")
                                except IOError, e:
                                    print "Unable to open plugin file '{0}': {1}".format(filename, e)
                                    continue

                                #load the module into our namespace
                                try:
                                    ## Try to load the module from the
                                    ## currently cached copy
                                    try:
                                        module = sys.modules[module_name]
                                    except KeyError:
                                        module = imp.load_source(module_name, dirpath + os.path.sep + filename, fd)
                                except ImportError, e:
                                    debug.debug("*** Unable to load module {0}: {1}".format(module_name, e))
                                    continue

                                fd.close()

                                #Is this module active?
                                try:
                                    if module.hidden:
                                        print "*** Will not load Module {0}: Module Hidden".format(module_name)
                                        continue
                                except AttributeError:
                                    pass

                                try:
                                    if not module.active:
                                        print "*** Will not load Module {0}: Module not active".format(module_name)
                                        continue
                                except AttributeError:
                                    pass

                                #find the module description
                                try:
                                    module_desc = module.description
                                except AttributeError:
                                    module_desc = module_name

                                ## Store information about this module here.
                                self.modules.append(module)
                                self.module_desc.append(module_desc)
                                self.module_paths.append(path)

                            else:
                                ## We already have the module in the cache:
                                module = self.modules[self.module_paths.index(path)]
                                module_desc = self.module_desc[self.module_paths.index(path)]

                            #Now we enumerate all the classes in the
                            #module to see which one is a ParentClass:
                            for cls in dir(module):
                                try:
                                    Class = module.__dict__[cls]
                                    if issubclass(Class, ParentClass) and Class != ParentClass:
                                        ## Check the class for consitancy
                                        try:
                                            self.check_class(Class)
                                        except AttributeError, e:
                                            print "Failed to load {0} '{1}': {2}".format(ParentClass, cls, e)
                                            continue

                                        ## Add the class to ourselves:
                                        self.add_class(ParentClass, module_desc, cls, Class, filename)

                                # Oops: it isnt a class...
                                except (TypeError, NameError) , e:
                                    continue

                        except TypeError, e:
                            print "Could not compile module {0}: {1}".format(module_name, e)
                            continue

    def add_class(self, _ParentClass, _module_desc, _cls, Class, filename):
        """ Adds the class provided to our self. This is here to be
        possibly over ridden by derived classes.
        """
        if Class not in self.classes:
            self.classes.append(Class)

            # Register any config options required by the class
            if hasattr(Class, 'register_options'):
                Class.register_options(config)

            self.filenames[self.get_name(Class)] = filename
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

    def import_module(self, name = None, load_as = None):
        """ Loads the named module into the system module name space.
        After calling this it is possible to do:

        import load_as

        in all other modules. Note that to avoid race conditions its
        best to only attempt to use the module after the registry is
        initialised (i.e. at run time not load time).

        @arg load_as: name to use in the systems namespace.
        @arg name: module name to import
        @note: If there are several modules of the same name (which
        should be avoided)  the last one encountered during registring
        should persist. This may lead to indeterminate behaviour.  
	"""

        if not load_as:
            load_as = name

        for module in self.modules:
            if name == module.__name__:
                sys.modules[load_as] = module
                return

        raise ImportError("No module by name {0}".format(name))

    def get_name(self, cls):
        try:
            return cls.name
        except AttributeError:
            return ("{0}".format(cls)).split(".")[-1]

    def filename(self, cls_name):
        return self.filenames.get(cls_name, "Unknown")

class VolatilityCommandRegistry(MemoryRegistry):
    """ A class to manage commands """
    def __getitem__(self, command_name):
        """ Return the command objects by name """
        return self.commands[command_name]

    def __init__(self, ParentClass):
        MemoryRegistry.__init__(self, ParentClass)
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

    def __init__(self, ParentClass):
        MemoryRegistry.__init__(self, ParentClass)
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
AS_CLASSES = None
PROFILES = None
SCANNER_CHECKS = None
EVENTS = None

## This is required for late initialization to avoid dependency nightmare.
def Init():
    ## LOCK will ensure that we only initialize once.
    global LOCK
    if LOCK:
        return
    LOCK = 1

    ## Register all shell commands:
    import volatility.commands as commands
    global PLUGIN_COMMANDS
    PLUGIN_COMMANDS = VolatilityCommandRegistry(commands.command)

    ## Register all the derived objects
    import volatility.addrspace as addrspace
    global AS_CLASSES
    AS_CLASSES = VolatilityObjectRegistry(addrspace.BaseAddressSpace)

    import volatility.obj as objmod
    global PROFILES
    PROFILES = VolatilityObjectRegistry(objmod.Profile)

    import volatility.scan as scan
    global SCANNER_CHECKS
    SCANNER_CHECKS = VolatilityObjectRegistry(scan.ScannerCheck)

    if config.INFO:
        print_info()
        sys.exit(0)
