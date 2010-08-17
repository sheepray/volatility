""" This module implements the volatility caching subsystem.

The volatility caching subsystem has the following design goals:

 1) Ability to cache arbitrary objects - The allows complex objects to
    be cached for later retrieval. For example, objects may be as
    simple as constants for KPCR addresses, to entire x86 page
    translation tables, or even hibernation decompression
    datastructures. To achieve this we use the standard python pickle
    system. In many use cases, the cache needs to facilitate
    persistant memoising of functions and generators (more on that
    below).

 2) Cached objects are stored by a hierarchical key namespace. Keys
    are specified in a URL notation. By default, relative URLs are
    interpreted relative to the memory image location (the value of
    the --location option). This scheme allows us to specify both
    global (per installation) and per image keys. For example given an
    image located in /tmp/foobar.img:

    - file:///tmp/foobar.img/kernel/debugging/KPCR refers to this
      image's KPCR location.

    - file:///tmp/foobar.img/address_spaces/memory_translation/pdpte
      refers to the cached page tables.

    - http://www.volatility.org/schema#configuration/renderer specifies
      the currently configured renderer (i.e. its a global setting).

 3) Storage of the cache is abstracted and selectable via the
 --cache_engine configuration variable. This allows the separation
 from the concerete storage of the cache and the abstraction of the
 cache in a running process.

Abstraction of Cache
--------------------

Within the running volatiltiy framework the cache appears as an
abstract tree with nodes inherited from the CacheNode class:

class CacheNode:
    def __init__(self, name, parent, payload = None):
        ''' Creates a new Cache node under the parent. The new node
        will carry the specified payload
        '''

    def __str__(self):
        ''' Produce a human readable version of the payload '''

    def set_payload(self, payload):
        ''' Update the current payload with the new specified payload '''

    def dump(self):
        ''' Dump the node to disk for later retrieval. This is
        normally called when the process has exited. '''

    def get_payload(self):
       ''' retrieve this node's payload '''

In order to check the cache, plugins issue the Cache.Check() function:

def Check(path, callback = None, cls = CacheNode):
    ''' Traverse the cache tree and retrieve the stored CacheNode.

    If there is no such stored CacheNode and callback is specified,
    attempt to create it using the cache_node_class with the payload
    returned from the callback. If callback is not specified we just
    return None.

Decorators
----------
You can also use the cache decorator to cache the results of any
function - this is probably the easiest way to apply caching to
existing code. For example, suppose we want to cache the results of
the psscan plugin:

class psscan(commands.command):
....
   @cache("/scanners/psscan")
   def calculate(self):
       .....

This will automatically create the CacheNode at the specified tree
location (note that since the URL is given as a relative URL it is
based at the current value of the --location - that means it applies
to the current memory image only).

Note that since calculate() returns a generator, the decorator will
also return a generator - It will not iterate over the calculate
method unnecessarily, but will yield results immediately. This does
not compromise performance in the case of a cache miss. Unfortunately
this also means that if the generator is stopped prematurely, we are
unable to cache the result set in the general case. This is the only
caveat on caching generators.

Storage classes
---------------
The cache system discussed above can be thought of as an abstract
construct in the process memory. To make it persistant on disk we have
the storage class (which can be selected using the --cache_engine
directive). The following cache engines are implemented:

File Storage
============
This is the default cache engine. We simply maintain a directory
structure which corresponds to the URL of the key after applying the
appropriate filesystem safe escaping operation. Objects are stored in
stand alone files using the pickle module.

Zip Storage
===========
This storage is essentially the same as the File storage above, except
that the cache directory for each image file is maintained in a Zip
file stored at the --cache_direcory directive with the same filename
as the image and a .zip extension.


Use cases
---------
The following common use cases are discussed:

1) Dynamic address spaces. In some address spaces memory address
   mappings can not be cached since they change all the time. For
   example in the firewire address space, it is incorrect to cache any
   page translations or scanning results etc. This is easily achieved
   by having the firewire address space store a BlockingCacheNode()
   instance at critical tree nodes. These prevent new nodes from being
   inserted into the tree and force a cache miss whenever any keys are
   searched under these nodes. Note that this still allows the cache
   to store the locations of things which might not change, even for
   live memory analysis, such as KPCR locations.

2) History logging and audit logs. Currently volatility works by
   running the framework multiple times on the same plugin with
   different command line options. This can be audited using the
   caching system by storing the current command line in a specific
   location using a specific CacheNode. This implementation can be
   used to append new commandlines to the same key. Configuration
   options can also become sticky in this way and remember the same
   values they had previously. This avoid users having to append many
   command line arguements (i.e. having to specify --profile, --kpcr,
   --dtb on every command line).

3) Unit tests.  Unit tests can be easily implemented using the caching
   subsystem as follows:

   - A test() method is added to each plugin. Usually this is actually
     the same as calculate().

   - This method is decorated to be cached under the
     "/tests/pluginname" key (i.e. relative to the current image). The
     CacheNode implementation is TestCacheNode which implements a
     special update_payload() method. The TestCacheNode also ensures
     that cache miss always occurs (by implementing a get_payload()
     method which returns None).

   - The update_payload() method ensures that the old payload and the
     new payloads are the same (if they are generators we ensure each
     member is the same as well - using the __eq__ method).

   The overall result is that unit tests can be run on any image as
   normal. If the particular test was never run on the image, we just
   cache the result of the plugin. If on the other hand, the result
   was already run on this image, the old result is compared to the
   new result and if a discrepancy is detected, an exception is
   raised.

   This testing framework is easy to implement and automatically
   guards against regression bugs. Since we use the __eq__ method of
   arbitrary objects, its also not limited to testing text string
   matches. For example, the object framework defines two objects are
   being equal if they are of the same type and they point at the same
   address. Even if the textual representation of the object's
   printouts has changed between versions, as long as the same objects
   are found in both cases no regressions will be reported.

4) Reporting framework. By having a persistant caching framework we
   now have the concept of a volatility analysis session. In other
   words, each new execution of volatility adds new information to
   what we know about the image. This new information is stored in the
   cache tree. We can actually produce a full report from the cache
   tree by traversing all the CacheNodes and calling their __str__()
   methods.

   If caching is introduced via decorators, the CacheNode already
   knows about the render() method of the plugin and can automatically
   generate the output from the plugin (this is very fast as the
   calculate is received from the cache). We therefore can generate a
   full report of all the plugins very quickly automatically.

   By default CacheNodes have an empty __str__() methods, so things
   like pas2kas lookup tables are not reported. Specialised reporting
   functions can be made if needed by implementing __str__() functions
   as needed.

"""
import types
import os
import urlparse
import volatility.conf as conf
import cPickle as pickle
config = conf.ConfObject()

## Where to stick the cache
default_cache_location = os.environ.get("XDG_CACHE_HOME") or os.environ.get("TEMP") or "/tmp/"

config.add_option("CACHE-DIRECTORY", default=default_cache_location,
                  help = "Directory where cache files are stored")

class CacheNode(object):
    """ Base class for Cache nodes """
    def __init__(self, name, stem, storage = None, payload = None):
        ''' Creates a new Cache node under the parent. The new node
        will carry the specified payload
        '''
        self.name = name
        self.payload = payload
        self.storage = storage
        self.stem = stem

    def __getitem__(self, item = ''):
        item_url = "{0}/{1}".format(self.stem, item)

        ## Try to load it from the storage manager
        try:
            result = self.storage.load(item_url)
            if result:
                return result
        except Exception, e:
            raise KeyError(e)

        ## Make a new empty Node instead on demand
        raise KeyError("item not found")

    def __str__(self):
        ''' Produce a human readable version of the payload. '''
        return ''

    def flatten_generators(self, item):
        """ A recursive function to flatten generators into lists """
        try:
            result = []
            for x in iter(item):
                flat_x = self.flatten_generators(x)
                result.append(flat_x)
        
            return result
        except TypeError:
            return item

    def set_payload(self, payload):
        ''' Update the current payload with the new specified payload '''
        self.payload = self.flatten_generators(payload)

    def dump(self):
        ''' Dump the node to disk for later retrieval. This is
        normally called when the process has exited. '''
        #url = "%s%s" % (self.stem, self.name)
        self.storage.dump(self.stem, self)

    def get_payload(self):
        """Retrieve this node's payload"""
        return self.payload

class BlockingNode(CacheNode):
    """Node that fails on all cache attempts and no-ops on cache storage attempts"""
    def __init__(self, name, stem, storage = None, payload = None):
        CacheNode.__init__(self, name, stem, None, None)

    def __getitem__(self, item = ''):
        return BlockingNode(item, '/'.join((self.stem, item)))

    def dump(self):
        """Ensure nothing gets dumped"""
        pass
    
    def get_payload(self):
        """Do not set a payload for a blocked cache node"""
        pass 

class CacheTree(object):
    """ An abstract structure which represents the cache tree """
    def __init__(self, storage = None, cls = CacheNode):
        self.storage = storage
        self.cls = cls
        self.root = self.cls('', '', storage = storage)

    def __getitem__(self, path):
        """Pythonic interface to the cache"""
        return self.check(path, cls = self.cls)
        
    def check(self, path, callback = None, cls = CacheNode):
        """ Retrieves the node at the path specified """
        ## Normalise the path
        path = urlparse.urljoin(config.LOCATION + "/", path)

        elements = path.split("/")
        current = self.root

        for e in elements:
            try:
                current = current[e]
            except KeyError:
                if current.stem:
                    next_stem = '/'.join((current.stem, e))
                else:
                    next_stem = e
                
                payload = None
                if callback is not None:
                    payload = callback()
                
                node = cls(e, next_stem, storage=self.storage, payload = payload)

                current = node

        return current

class CacheStorage(object):
    """ The base class for implementation storing the cache. """
    ## Characters allowed in filenames
    printables = "0123456789@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_."

    def encode(self, string):
        result = ''
        for x in string:
            if x in self.printables:
                result += x
            else:
                result += "%{0:02X}".format(ord(x))

        return result

    def filename(self, url):
        if url.startswith(config.LOCATION):
            path = os.path.normpath(url[len(config.LOCATION):])
        else:
            raise RuntimeError("Storing non relative URLs is not supported now ({0})".format(url))

        path = "/".join((config.CACHE_DIRECTORY, os.path.basename(config.LOCATION) + ".cache", path)) + '.pickle'
        parsed = urlparse.urlparse(path)
        ## Make sure path does not have any special chars
        path = '/'.join([ self.encode(x) for x in parsed.path.split("/") ]) #pylint: disable-msg=E1101

        return path

    def load(self, url):
        filename = self.filename(url)

        if config.DEBUG:
            print "CACHE: Loading from {0}".format(filename)
        data = open(filename).read()

        return pickle.loads(data)

    def dump(self, url, payload):
        filename = self.filename(url)

        if config.DEBUG:
            print "CACHE: Dumping filename {0}".format(filename)
        ## Check that the directory exists
        directory = os.path.dirname(filename)
        if not os.access(directory, os.R_OK | os.W_OK | os.X_OK):
            os.makedirs(directory)

        ## Ensure that the payload is flattened - i.e. all generators are converted to lists for pickling
        data = pickle.dumps(payload)
        fd = open(filename, 'w')
        fd.write(data)
        fd.close()

CACHE = CacheTree(CacheStorage())

def disable_caching(_option, _opt_str, _value, _parser):
    """Turns off caching by replacing the tree with one that only takes BlockingNodes"""
    if config.DEBUG:
        print "Disabling Caching"
    # Feels filthy using the global keyword,
    # but I can't figure another way to ensure that
    # the code gets called and overwrites the outer scope
    global CACHE
    CACHE = CacheTree(CacheStorage(), BlockingNode)

config.add_option("NO-CACHE", default = None, action = 'callback',
                  callback = disable_caching,
                  help = "Disable caching")

class CacheDecorator(object):
    """ This decorator will memoise a function in the cache """
    def __init__(self, path):
        self.path = path
        self.node = None

    def generate(self, path, g):
        """ Special handling for generators. We pass each iteration
        back immediately, and keep it in a list. Note that if the
        generator is aborted, the cache is not dumped.
        """
        payload = []
        for x in g:
            payload.append(x)
            yield x

        self.dump(path, payload)

    def dump(self, path, payload):
        self.node = CACHE[path]
        self.node.set_payload(payload)
        self.node.dump()

    def __call__(self, f):
        def wrapper(s, *args, **kwargs):
            ## Interpolate the path
            path = self.path % dict(class_name = s.__class__.__name__)
            ## Check if the result can be retrieved
            self.node = CACHE[self.path]
            if self.node.get_payload():
                return self.node.get_payload()

            result = f(s, *args, **kwargs)

            ## If the wrapped function is a generator we need to
            ## handle it especially
            if type(result) == types.GeneratorType:
                return self.generate(path, result)
            
            self.dump(path, result)
            return result

        return wrapper

class Testable(object):
    """ This is a mixin that makes a class response to the unit tests 
    
        It must be inheritted *after* the command class
    """

    def calculate(self):
        """Empty function used to allow mixin"""

    ## This forces the test to be memoised with a key name derived from the class name
    @CacheDecorator("tests/unittests/%(class_name)s")
    def test(self):
        ## This forces iteration over all keys - this is required in order
        ## to flatten the full list for the cache
        return [ x for x in self.calculate() ]
