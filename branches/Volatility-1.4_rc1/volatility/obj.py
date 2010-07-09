# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Copyright (C) 2005,2006 4tphi Research
# Author: {npetroni,awalters}@4tphi.net (Nick Petroni and AAron Walters)
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

import sys
if __name__ == '__main__':
    sys.path.append(".")
    sys.path.append("..")

import re
import struct, copy, operator
import volatility.registry as MemoryRegistry
import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.conf as conf
config = conf.ConfObject()

class Curry:
    """ This class makes a curried object available for simple inlined functions.

    A curried object represents a function which has some of its
    arguements pre-determined. For example imagine there is a
    function:

    def foo(a=a,b=b):
        pass

    curry=Curry(foo,a=1)   returns a function pointer.

    curry(3) is the same as calling foo(a=1,b=3).
    For more information see the Oreilly Python Cookbook.

    This implementation is used for old python versions since in
    modern pythons its in the standard library (See below)
    """
    def __init__(self, function, *args, **kwargs):
        """ Initialised the curry object with the correct function."""
        self.fun = function
        self.pending = args[:]
        self.kwargs = kwargs.copy()

    def __call__(self, *args, **kwargs):
        if kwargs and self.kwargs:
            kw = self.kwargs.copy()
            kw.update(kwargs)
        else:
            kw = kwargs or self.kwargs
            
        return self.fun(*(self.pending+args), **kw)

try:
    ## Curry is now a standard python feature
    import functools

    Curry = functools.partial
except:
    pass

import traceback

def get_bt_string(_e=None):    
    return ''.join(traceback.format_stack()[:-3])

class FormatSpec(object):
    def __init__(self, string = '', **kwargs):
        self.fill = ''
        self.align = ''
        self.sign = ''
        self.altform = False
        self.minwidth = -1
        self.precision = -1
        self.formtype = ''

        if string != '':
            self.from_string(string)

        # Ensure we parse the remaining arguments after the string to that they override
        self.from_specs(**kwargs)

    def from_specs(self, fill=None, align=None, sign=None, altform=None, minwidth=None, precision=None, formtype=None):
        ## Allow setting individual elements using kwargs 
        if fill is not None:
            self.fill = fill 
        if align is not None:
            self.align = align
        if sign is not None:
            self.sign = sign
        if altform is not None:
            self.altform = altform 
        if minwidth is not None:
            self.minwidth = minwidth
        if precision is not None:
            self.precision = precision
        if formtype is not None:
            self.formtype = formtype

    def from_string(self, formatspec):
        # Format specifier regular expression
        regexp = "\A(.[<>=^]|[<>=^])?([-+ ]|\(\))?(#?)(0?)(\d*)(\.\d+)?(.)?\Z"
    
        match = re.search(regexp, formatspec)
        
        if match is None:
            raise ValueError("Invalid format specification")
        
        if match.group(1):
            fillalign = match.group(1)
            if len(fillalign) > 1:
                self.fill = fillalign[0]
                self.align = fillalign[1]
            elif fillalign:
                self.align = fillalign
    
        if match.group(2):
            self.sign = match.group(2)
        if match.group(3):
            self.altform = len(match.group(3)) > 0
        if len(match.group(4)):
            if self.fill == "":
                self.fill = "0"
                if self.align == "":
                    self.align = "="
        if match.group(5):
            self.minwidth = int(match.group(5))
        if match.group(6):
            self.precision = int(match.group(6)[1:])
        if match.group(7):
            self.formtype = match.group(7)

    def to_string(self):
        formatspec = self.fill + self.align + self.sign
        if self.sign == '(':
            formatspec += ')'
        if self.altform:
            formatspec += '#'
        if self.minwidth >= 0:
            formatspec += str(self.minwidth)
        if self.precision >= 0:
            formatspec += '.' + str(self.precision)
        formatspec += self.formtype
    
        return formatspec

    def __str__(self):
        return self.to_string()

class NoneObject(object):
    """ A magical object which is like None but swallows bad
    dereferences, __getattribute__, iterators etc to return itself.

    Instantiate with the reason for the error.
    """
    def __init__(self, reason='', strict=False):
        self.reason = reason
        self.strict = strict
        if strict:
            self.bt = get_bt_string()

    def __str__(self):
        ## If we are strict we blow up here
        if self.strict:
            result = "Error: {0} n{1}".format(self.reason, self.bt)
            print result
            sys.exit(0)
        else:
            return "Error: {0}".format(self.reason)

    def write(self, data):
        """Write procedure only ever returns False"""
        return False

    ## Behave like an empty set
    def __iter__(self):
        return self

    def __len__(self):
        return 0

    def __format__(self, formatspec):
        spec = FormatSpec(string=formatspec, fill="-", align=">")
        return format('-', str(spec))
    
    def next(self):
        raise StopIteration()

    def __getattribute__(self, attr):
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            return self

    def __bool__(self):
        return False

    def __nonzero__(self):
        return False

    def __eq__(self, other):
        return (other is None)

    def __ne__(self, other):
        return not self.__eq__(other)

    ## Make us subscriptable obj[j]
    def __getitem__(self, item):
        return self

    def __add__(self, x):
        return self

    def __sub__(self, x):
        return self

    def __int__(self):
        return -1

    def __lshift__(self, other):
        return self

    def __rshift__(self, other):
        return self

    def __or__(self, other):
        return self

    def __call__(self, *arg, **kwargs):
        return self
        
def Object(theType, offset, vm, parent=None, name=None, **kwargs):
    """ A function which instantiates the object named in theType (as
    a string) from the type in profile passing optional args of
    kwargs.
    """
    name = name or theType
    offset = int(offset)
    
    ## If we cant instantiate the object here, we just error out:
    if not vm.is_valid_address(offset):
        return NoneObject("Invalid Address 0x{0:08X}, instantiating {1}".format(offset, name),
                          strict=vm.profile.strict)

    if theType in vm.profile.types:
        result = vm.profile.types[theType](offset=offset, vm=vm, name=name,
                                           parent=parent)
        return result
    

    # Need to check for any derived object types that may be 
    # found in the global memory registry.
    if theType in MemoryRegistry.OBJECT_CLASSES.objects:
        return MemoryRegistry.OBJECT_CLASSES[theType](
            theType,
            offset,
            vm = vm, parent=parent, name=name,
            **kwargs)

    ## If we get here we have no idea what the type is supposed to be? 
    ## This is a serious error.
    debug.debug("Cant find object {0} in profile {1}???".format(theType, vm.profile), level = 3)

class BaseObject(object):
    def __init__(self, theType, offset, vm, parent=None, name=None):
        self.vm = vm
        self.parent = parent
        self.profile = vm.profile
        self.offset = offset
        self.name = name
        self.theType = theType
        
    def rebase(self, offset):
        return self.__class__(self.theType, offset, vm=self.vm)

    def proxied(self, attr):
        return None

    def newattr(self, attr, value):
        """Sets a new attribute after the object has been created"""
        return BaseObject.__setattr__(self, attr, value)
    
    def write(self, value):
        """Function for writing the object back to disk"""
        pass

    def __getattr__(self, attr):
        """ This is only useful for proper methods (not ones that
        start with __ )
        """
        ## Search for the attribute of the proxied object
        proxied = self.proxied(attr)
        # Don't do a __nonzero__ check on proxied or things like '' will fail
        if proxied is None:
            raise AttributeError("Unable to resolve attribute %s on %s" % (attr, self.name))
        
        return getattr(proxied, attr)

    def __setattr__(self, attr, value):
        try:
            object.__setattr__(self, attr, value)
        except AttributeError:
            pass
            # print "Will set {0} to {1}".format(attr, value)

    def __nonzero__(self):
        """ This method is called when we test the truth value of an
        Object. In volatility we consider an object to have True truth
        value only when its a valid object. Its possible for example
        to have a Pointer object which is not valid - this will have a
        truth value of False.

        You should be testing for validity like this:
        if X:
           # object is valid

        Do not test for validity like this:

        if int(X) == 0:

        or if X is None: .....

        the later form is not going to work when X is a NoneObject. 
        """
        result = self.vm.is_valid_address(self.offset)
        return result
    
#    def __eq__(self, other):
#        if isinstance(other, BaseObject):
#            return (self.__class__ == other.__class__) and (self.offset == other.offset)
#        else:
#            return NotImplemented

    def __hash__(self):
        return hash(self.name) ^ hash(self.offset)

    def has_member(self, memname):
        return False

    def m(self, memname):
        return self.get_member(memname)

    def get_member(self, memname):
        raise AttributeError("No member {0}".format(memname))

    def get_member_offset(self, memname, relative=False):
        return self.offset

    def is_null(self):
        return False

    def is_valid(self):
        return self.vm.is_valid_address(self.offset)

    def dereference(self):
        return NoneObject("Can't dereference {0}".format(self.name), self.profile.strict)

    def dereference_as(self, derefType):
        return Object(derefType, self.v(), \
                         self.vm, parent=self)

    def cast(self, castString):
        return Object(castString, self.offset, self.vm)

    def v(self):
        """ Do the actual reading and decoding of this member
        """
        return NoneObject("No value for {0}".format(self.name), self.profile.strict)

    def __format__(self, formatspec):
        return format(self.v(), formatspec)

    def get_bytes(self, amount=None):
        if amount == None:
            # FIXME: Figure out what self.size() should be?
            # amount = self.size()
            pass

        return self.vm.read(self.offset, amount)

    def __str__(self):
        return str(self.v())

    def __repr__(self):
        return "[{0} {1}] @ 0x{2:08X}".format(self.__class__.__name__, self.name or '',
                                              self.offset)

    def d(self):
        """Display diagnostic information"""
        return self.__repr__()

def CreateMixIn(mixin):
    def make_method(name):
        def method(self, *args, **kw):
            proxied = self.proxied(name)
            try:
                ## Try to coerce the other in case its also a proxied
                ## class
                args = list(args)
                args[0] = args[0].proxied(name)
            except (AttributeError, IndexError):
                pass

            try:
                method = getattr(operator, name)
                args = [proxied] + args
            except AttributeError:
                method = getattr(proxied, name)
            
            return method(*args, **kw)
        
        return method
    
    for name in mixin._specials:
        setattr(mixin, name, make_method(name))

class NumericProxyMixIn(object):
    """ This MixIn implements the numeric protocol """
    _specials = [
        ## Number protocols
        '__add__', '__sub__', '__mul__', '__floordiv__', '__mod__', '__divmod__',
        '__pow__', '__lshift__', '__rshift__', '__and__', '__xor__', '__div__',
        '__truediv__', '__radd__', '__rsub__', '__rmul__', '__rdiv__', '__rtruediv__',
        '__rfloordiv__', '__rmod__', '__rdivmod__', '__rpow__', '__rlshift__',
        '__rrshift__', '__rand__', '__rxor__', '__ror__', '__neg__', '__pos__',
        '__abs__', '__invert__', '__int__', '__long__', '__float__', '__oct__',
        '__hex__',

        ## Comparisons
        '__lt__', '__le__', '__eq__', '__ne__', '__ge__', '__gt__', '__index__',
        
        ## Formatting
        '__format__',
        ]


CreateMixIn(NumericProxyMixIn)

class NativeType(BaseObject, NumericProxyMixIn):
    def __init__(self, theType, offset, vm, parent=None,
                 format_string=None, name=None, **args):
        BaseObject.__init__(self, theType, offset, vm, parent=parent, name=name)
        NumericProxyMixIn.__init__(self)
        self.format_string = format_string

    def write(self, data):
        """Writes the data back into the address space"""
        output = struct.pack(self.format_string, data)
        return self.vm.write(self.offset, output)

    def rebase(self, offset):
        return self.__class__(None, offset, self.vm, format_string=self.format_string)

    def proxied(self, attr):
        return self.v()

    def size(self):
        return struct.calcsize(self.format_string)

    def v(self):
        data = self.vm.read(self.offset, self.size())
        if not data:
            return NoneObject("Unable to read {0} bytes from {1}".format(self.size(), self.offset))
        
        (val, ) = struct.unpack(self.format_string, data)
                
        return val

    def cdecl(self):
        return self.name

    def __repr__(self):
        return " [{0}]: {1}".format(self.theType, self.v())
    
    def d(self):
        return " [{0} {1} | {2}]: {3}".format(self.__class__.__name__, self.name or '',
                                              self.theType, self.v())

class BitField(NativeType):
    """ A class splitting an integer into a bunch of bit. """
    def __init__(self, theType, offset, vm, parent=None, 
                 start_bit=0, end_bit=32, name=None, **args):
        NativeType.__init__(self, theType, offset, vm, parent=parent, name=name)
        self.format_string = 'L'
        self.start_bit = start_bit
        self.end_bit = end_bit

    def v(self):
        i = NativeType.v(self)
        return (i & ( (1 << self.end_bit) - 1)) >> self.start_bit

    def write(self, data):
        data = data << self.start_bit
        return NativeType.write(self, data)

class Pointer(NativeType):
    def __init__(self, theType, offset, vm, parent=None, profile=None, target=None, name=None):
        NativeType.__init__(self, theType, offset = offset, vm=vm, name=name,
                            parent=parent, profile=profile)
        self.format_string = "=L"
        
        if theType:
            self.target = Curry(Object, theType)
        else:
            self.target = target

    def is_valid(self):
        """ Returns if what we are pointing to is valid """
        return self.vm.is_valid_address(self.v())

    def dereference(self):
        offset = self.v()
        if self.vm.is_valid_address(offset):
            result = self.target(offset=offset, vm=self.vm, parent=self.parent,
                                 name=self.name)
            return result
        else:
            return NoneObject("Pointer {0} invalid".format(self.name), self.profile.strict)

    def cdecl(self):
        return "Pointer {0}".format(self.v())

    def __nonzero__(self):
        return bool(self.is_valid())

    def __repr__(self):
        target = self.dereference()
        return "<{0} pointer to [0x{1:08X}]>".format(target.__class__.__name__, self.v())

    def d(self):
        target = self.dereference()
        return "<{0} {1} pointer to [0x{2:08X}]>".format(target.__class__.__name__, self.name or '', self.v()) 

    def __getattribute__(self, attr):
        try:
            return super(Pointer, self).__getattribute__(attr)
        except AttributeError:
            ## We just dereference ourself
            result = self.dereference()

            #if isinstance(result, CType):
            #    return result.m(attr)
            return result.__getattribute__(attr)

class Void(NativeType):
    def __init__(self, theType, offset, vm, parent=None,
                 format_string=None, **args):
        NativeType.__init__(self, theType, offset, vm, parent=None)
        self.format_string = "=L"

    def cdecl(self):
        return "0x{0:08X}".format(self.v())
    
    def __repr__(self):
        return "Void (0x{0:08X})".format(self.v())

    def d(self):
        return "Void[{0} {1}] (0x{2:08X})".format(self.__class__.__name__, self.name or '', self.v())

    def __nonzero__(self):
        return bool(self.dereference())

    def dereference_as(self, derefType):
        return Object(derefType, self.v(), \
                         self.vm, parent=self)

class Array(BaseObject):
    """ An array of objects of the same size """
    def __init__(self, targetType=None, offset=0, vm=None, parent=None,
                 count=1, name=None, target=None):
        ## Instantiate the first object on the offset:
        BaseObject.__init__(self, targetType, offset, vm,
                        parent=parent, name=name)
        try:
            count = count(parent)
        except TypeError, _e:
            pass
        
        self.count = int(count)

        self.original_offset = offset
        if targetType:
            self.target = Curry(Object, targetType)
        else:
            self.target = target

        self.current = self.target(offset=offset, vm=vm, parent=self,
                                       name= name)
        if self.current.size()==0:
            ## It is an error to have a zero sized element
            debug.debug("Array with 0 sized members???", level=10)
            debug.b()

    def size(self):
        return self.count * self.current.size()

    def __iter__(self):
        ## This method is better than the __iter__/next method as it
        ## is reentrant
        for position in range(0, self.count):
            
            ## We don't want to stop on a NoneObject.  Its
            ## entirely possible that this array contains a bunch of
            ## pointers and some of them may not be valid (or paged
            ## in). This should not stop us though we just return the
            ## invalid pointers to our callers.  It's up to the callers
            ## to do what they want with the array.
            if (self.current == None):
                return

            offset = self.original_offset + position * self.current.size()

            ## Instantiate the target here:
            if self.vm.is_valid_address(offset):
                yield self.target(offset = offset, vm=self.vm,
                                  parent=self,
                                  name="{0} {1}".format(self.name, position))
            else:
                yield NoneObject("Array {0}, Invalid position {1}".format(self.name, position),
                                 self.profile.strict)
        
    def __repr__(self):
        result = [ x.__str__() for x in self ]
        return "<Array {0}>".format(",".join(result))

    def d(self):
        result = [ x.__str__() for x in self ]
        return "<Array[{0} {1}] {2}>".format(self.__class__.__name__, self.name or '', ",".join(result))

    def __eq__(self, other):
        if self.count != len(other):
            return False
        
        for i in range(self.count):
            if not self[i] == other[i]:
                return False

        return True
    
    def __getitem__(self, pos):        
        ## Check if the offset is valid
        offset = self.original_offset + \
                 pos * self.current.size()
        if pos <= self.count and self.vm.is_valid_address(offset):
            return self.target(offset = offset,
                               vm=self.vm, parent=self)
        else:
            return NoneObject("Array {0} invalid member {1}".format(self.name, pos),
                              self.profile.strict)
    
class CType(BaseObject):
    """ A CType is an object which represents a c struct """
    def __init__(self, theType, offset, vm, parent=None, members=None, name=None, size=0):
        """ This must be instantiated with a dict of members. The keys
        are the offsets, the values are Curried Object classes that
        will be instantiated when accessed.
        """
        if not members:
            raise RuntimeError()
        
        BaseObject.__init__(self, theType, offset, vm, parent=parent, name=name)
        self.members = members
        self.offset = offset
        self.struct_size = size
        self.__initialized = True

    def size(self):
        return self.struct_size

    def __repr__(self):
        return "[{0} {1}] @ 0x{2:08X}".format(self.__class__.__name__, self.name or '', 
                                     self.offset)
    def d(self):
        result = self.__repr__() + "\n"
        for k in self.members.keys():
            result += " {0} -\n {1}\n".format( k, self.m(k))

        return result

    def v(self):
        """ When a struct is evaluated we just return our offset.
        """
        return self.offset

    def m(self, attr):
        try:
            offset, cls = self.members[attr]
        except KeyError:
            ## hmm - tough choice - should we raise or should we not
            #return NoneObject("Struct {0} has no member {1}".format(self.name, attr))
            raise AttributeError("Struct {0} has no member {1}".format(self.name, attr))

        try:
            ## If offset is specified as a callable its an absolute
            ## offset
            offset = int(offset(self))
        except TypeError:
            ## Otherwise its relative to the start of our struct
            offset = int(offset) + int(self.offset)

        result = cls(offset = offset, vm=self.vm,
                     parent=self, name=attr)

        return result

    def __getattribute__(self, attr):
        try:
            return object.__getattribute__(self, attr)
        except AttributeError:
            pass

        try:
            return object.__getattribute__(self, "_" + attr)(attr)
        except:
            pass
        
        return self.m(attr)

    def __setattr__(self, attr, value):
        """Change underlying members"""
        # Special magic to allow initialization
        if not self.__dict__.has_key('_CType__initialized'):  # this test allows attributes to be set in the __init__ method
            return BaseObject.__setattr__(self, attr, value)
        elif self.__dict__.has_key(attr):       # any normal attributes are handled normally
            return BaseObject.__setattr__(self, attr, value)
        else:
            if config.WRITE:
                obj = self.m(attr)
                if not obj.write(value):
                    raise ValueError("Error writing value to member " + attr)
        # If you hit this, consider using obj.newattr('attr', value)
        raise ValueError("Attribute " + attr + " was set after object initialization")
    
## Profiles are the interface for creating/interpreting
## objects

class Profile:
    """ A profile is a collection of types relating to a certain
    system. We parse the abstract_types and join them with
    native_types to make everything work together.
    """
    native_types = {}
    abstract_types = {}
    overlay = {}
    
    def __init__(self, strict=False):
        self.types = {}
        self.typeDict = {}
        self.overlayDict = {}
        self.strict = strict
        
        self.add_types(self.abstract_types, self.overlay)

    def add_types(self, abstract_types, overlay=None):
        overlay = overlay or {}

        ## we merge the abstract_types with self.typeDict and then recompile
        ## the whole thing again. This is essential because
        ## definitions may have changed as a result of this call, and
        ## we store curried objects (which might keep their previous
        ## definitions).
        for k, v in abstract_types.items():
            original = self.typeDict.get(k, [0, {}])
            original[1].update(v[1])
            if v[0]:
                original[0] = v[0]
            self.typeDict[k] = original

        for k, v in overlay.items():
            original = self.overlayDict.get(k, [None, {}])
            original[1].update(v[1])
            if v[0]:
                original[0] = v[0]
                
            self.overlayDict[k] = original

        # Load the native types
        self.types = {}
        for nt, value in self.native_types.items():
            if type(value) == list:
                self.types[nt] = Curry(NativeType, nt, format_string=value[1])

        for name in self.typeDict.keys():
            ## We need to protect our virgin overlay dict here - since
            ## the following functions modify it, we need to make a
            ## deep copy:
            self.types[name] = self.convert_members(
                name, self.typeDict, copy.deepcopy(self.overlayDict))
        
    def list_to_type(self, name, typeList, typeDict=None):
        """ Parses a specification list and returns a VType object.

        This function is a bit complex because we support lots of
        different list types for backwards compatibility.
        """
        ## This supports plugin memory objects:
        #if typeList[0] in MemoryRegistry.OBJECT_CLASSES.objects:
        #    print "Using plugin for %s" % 

        try:
            args = typeList[1]

            if type(args)==dict:
                ## We have a list of the form [ ClassName, dict(.. args ..) ]
                return Curry(Object, theType=typeList[0], name=name,
                             **args)
        except (TypeError, IndexError), _e:
            pass

        ## This is of the form [ 'void' ]
        if typeList[0] == 'void':
            return Curry(Void, Void, name=name)

        ## This is of the form [ 'pointer' , [ 'foobar' ]]
        if typeList[0] == 'pointer':
            try:
                target = typeList[1]
            except IndexError:
                raise RuntimeError("Syntax Error in pointer type defintion for name {0}".format(name))
            
            return Curry(Pointer, None,
                         name = name,
                         target=self.list_to_type(name, target, typeDict))

        ## This is an array: [ 'array', count, ['foobar'] ]
        if typeList[0] == 'array':
            return Curry(Array, None,
                         name = name, count=typeList[1],
                         target=self.list_to_type(name, typeList[2], typeDict))

        ## This is a list which refers to a type which is already defined
        if typeList[0] in self.types:
            return Curry(self.types[typeList[0]], name=name)

        ## Does it refer to a type which will be defined in future? in
        ## this case we just curry the Object function to provide
        ## it on demand. This allows us to define structures
        ## recursively.
        ##if typeList[0] in typeDict:
        if 1:
            try:
                args = typeList[1]
            except IndexError:
                args = {}
            
            obj_name = typeList[0]
            return Curry(Object, obj_name, name=name, **args)

        ## If we get here we have no idea what this list is
        #raise RuntimeError("Error in parsing list {0}".format(typeList))
        print "Warning - Unable to find a type for {0}, assuming int".format(typeList[0])
        return Curry(self.types['int'], name=name)

    def get_obj_offset(self, name, member):
        """ Returns a members offset within the struct """
        class dummy:
            profile = self
        tmp = self.types[name](name, dummy())
        offset, _cls = tmp.members[member]
        
        return offset

    def get_obj_size(self, name):
        """Returns the size of a struct"""
        class dummy:
            profile = self
        tmp = self.types[name](name, dummy())
        return tmp.size()

    def apply_overlay(self, type_member, overlay):
        """ Update the overlay with the missing information from type.

        Basically if overlay has None in any slot it gets applied from vtype.
        """
        if not overlay:
            return type_member

        if type(type_member)==dict:
            for k, v in type_member.items():
                if k not in overlay:
                    overlay[k] = v
                else:
                    overlay[k] = self.apply_overlay(v, overlay[k])
                    
        elif type(overlay)==list:
            if len(overlay) != len(type_member):
                return overlay

            for i in range(len(overlay)):
                if overlay[i] == None:
                    overlay[i] = type_member[i]
                else:
                    overlay[i] = self.apply_overlay(type_member[i], overlay[i])

        return overlay
        
    def convert_members(self, cname, typeDict, overlay):
        """ Convert the member named by cname from the c description
        provided by typeDict into a list of members that can be used
        for later parsing.

        cname is the name of the struct.
        
        We expect typeDict[cname] to be a list of the following format

        [ Size of struct, members_dict ]

        members_dict is a dict of all members (fields) in this
        struct. The key is the member name, and the value is a list of
        this form:

        [ offset_from_start_of_struct, specification_list ]

        The specification list has the form specified by self.list_to_type() above.

        We return a list of CTypeMember objects. 
        """
        ctype = self.apply_overlay(typeDict[cname], overlay.get(cname))
        members = {}
        size = ctype[0]
        for k, v in ctype[1].items():
            if v[0] == None:
                print "Error - {0} has no offset in object {1}. Check that vtypes has a concrete definition for it.".format(k, cname)
            members[k] = (v[0], self.list_to_type(k, v[1], typeDict))

        ## Allow the plugins to over ride the class constructor here
        if MemoryRegistry.OBJECT_CLASSES and \
               cname in MemoryRegistry.OBJECT_CLASSES.objects:
            cls = MemoryRegistry.OBJECT_CLASSES[cname]
        else:
            cls = CType
        
        return Curry(cls, cls, members=members, size=size)

if __name__ == '__main__':
    ## If called directly we run unit tests on this stuff
    import unittest

    config.parse_options()
    MemoryRegistry.Init()

    class ObjectTests(unittest.TestCase):
        """ Tests the object implementation. """
        def test001ProxyObject(self):
            ## Check the proxying of various objects
            test_data = "hello world"
            address_space = addrspace.BufferAddressSpace(data=test_data)
            o = Object('String', offset=0, vm=address_space, length=len(test_data))
            
            print o.find("world"), o.upper(), o.lower()

            o = Object('unsigned int', offset=0, vm=address_space, length=len(test_data))
            O = o.v()
            print type(o), type(O)
            self.assertEqual(o, O)
            self.assertEqual(o + 5, O + 5)
            self.assertEqual(o + o, O + O)
            self.assertEqual(o * 2, O * 2)
            self.assertEqual(o * o, O * O)

            self.assertEqual(o > 5, O > 5)
            self.assertEqual(o < 1819043181, O < 1819043181)
            self.assertEqual(o <= 1819043181, O <= 1819043181)
            self.assertEqual(o == 1819043181, O == 1819043181)
            self.assertEqual(o < o, O < O)

            self.assertEqual(o / 4, O / 4)
            self.assertEqual(o << 2, O << 2)
            self.assertEqual(o >> 2, O >> 2)
            self.assertEqual(o / 3, O / 3)
            self.assertEqual(float(o), float(O))
            
            print o, o+5, o * 2, o / 2, o << 3, o & 0xFF, o + o

        def test01SimpleStructHandling(self):
            """ Test simple struct handling """
            mytype = {
                "HEADER": [ 0x20,
                            { 'MAGIC': [ 0x00, ['array', 3, ['char'] ]],
                              'Size': [ 0x04, ['unsigned int']],
                              'Count': [ 0x08, ['unsigned short int']],
                              }],
                }

            test_data = "ABAD\x06\x00\x00\x00\x02\x00\xff\xff"
            address_space = addrspace.BufferAddressSpace(data=test_data)
            address_space.profile.add_types(mytype)
            
            o = Object('HEADER', offset=0, vm=address_space)
            ## Can we decode ints?
            self.assertEqual(o.Size.v(), 6)
            self.assertEqual(int(o.Size), 6)
            self.assertEqual(o.Size + 6, 12)
            self.assertEqual(o.Size - 3, 3)
            self.assertEqual(o.Size + o.Count, 8)
            
            ## This demonstrates how array members print out
            print o.MAGIC[0], o.MAGIC[1]

            ## test comparison of array members
            self.assertEqual(o.MAGIC[0], 'A')
            self.assertEqual(o.MAGIC[0], o.MAGIC[2])
            self.assertEqual(o.MAGIC, ['A', 'B', 'A'])
            self.assertEqual(o.MAGIC, 'ABA')
            
            ## Iteration over arrays:
            tmp = 'ABA'
            count = 0
            for t in o.MAGIC:
                self.assertEqual(t, tmp[count])
                count += 1

        def test02Links(self):
            """ Tests intrastruct links, pointers etc """
            mytype = {
                '_LIST_ENTRY' : [ 0x8, { \
                      'Flink' : [ 0x0, ['pointer', ['_LIST_ENTRY']]], \
                      'Blink' : [ 0x4, ['pointer', ['_LIST_ENTRY']]], \
                      } ],
                '_HANDLE_TABLE' : [ 0x44, { \
                      'TableCode' : [ 0x0, ['unsigned long']], \
                      'UniqueProcessId' : [ 0x8, ['pointer', ['void']]], \
                      'HandleTableList' : [ 0x1c, ['_LIST_ENTRY']], \
                      'HandleCount' : [ 0x3c, ['long']], \
                      } ],
                }

            test_data = '\x01\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\\\x00\x00\x00\\\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

            address_space = addrspace.BufferAddressSpace(data=test_data)
            address_space.profile.add_types(mytype)
            
            o = Object('_HANDLE_TABLE', offset=0, vm=address_space)

            self.assertEqual(o.TableCode, 1)
            self.assertEqual(o.UniqueProcessId, 0x1c)
            self.assertEqual(o.UniqueProcessId.dereference(), 0x5c)
            self.assertEqual(o.UniqueProcessId.dereference_as("unsigned int"), 0x5c)

            return
            n = o.HandleTableList.Flink
            self.assertEqual(n.TableCode, 3)
            self.assertEqual(n.HandleCount, 5)

            ## Make sure next.prev == o
            self.assertEqual(n.HandleTableList.Blink, o)
            self.assertEqual(n.HandleTableList.Blink.TableCode, 1)
                        
    suite = unittest.makeSuite(ObjectTests)
    res = unittest.TextTestRunner(verbosity=2).run(suite)
