# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

""" This file defines some basic types which might be useful for many
OS's
"""
# FIXME: It's currently important these are imported here, otherwise
# they don't show up in the MemoryObjects registry
from volatility.obj import BitField, Pointer, Void, Array, CType #pylint: disable-msg=W0611
import volatility.obj as obj
import volatility.debug as debug #pylint: disable-msg=W0611

class String(obj.NativeType):
    """Class for dealing with Strings"""
    def __init__(self, theType, offset, vm=None,
                 length=1, parent=None, profile=None, name=None, **args):
        ## Allow length to be a callable:
        try:
            length = length(parent)
        except TypeError:
            pass
        
        ## length must be an integer
        obj.NativeType.__init__(self, theType, offset, vm, parent=parent, profile=profile,
                            name=name, format_string="{0}s".format(length))

    def proxied(self, name):
        """ Return an object to be proxied """
        return self.__str__()
    
    def __str__(self):
        data = self.v()
        ## Make sure its null terminated:
        result = data.split("\x00")[0]
        if not result:
            return ""
        return result
    
    def __format__(self, formatspec):
        return format(self.__str__(), formatspec)
    
    def __add__(self, other):
        """Set up mappings for concat"""
        return str(self) + other
    
    def __radd__(self, other):
        """Set up mappings for reverse concat"""
        return other + str(self)

class Flags(obj.NativeType):
    """ This object decodes each flag into a string """
    ## This dictionary maps each bit to a String
    bitmap = {}

    ## This dictionary maps a string mask name to a bit range
    ## consisting of a list of start, width bits
    maskmap = {}

    def __init__(self, targetType=None, offset=0, vm=None, parent=None,
                 bitmap=None, name=None, maskmap=None, target="unsigned long",
                 **args):
        if bitmap:
            self.bitmap = bitmap

        if maskmap:
            self.maskmap = maskmap

        self.target = obj.Object(target, offset=offset, vm=vm, parent=parent)
        obj.NativeType.__init__(self, targetType, offset, vm, parent, **args)

    def v(self):
        return self.target.v()

    def __str__(self):
        result = []
        value = self.v()
        keys = self.bitmap.keys()
        keys.sort()
        for k in keys:
            if value & (1 << self.bitmap[k]):
                result.append(k)

        return ', '.join(result)

    def __format__(self, formatspec):
        return format(self.__str__(), formatspec)

    def __getattr__(self, attr):
        maprange = self.maskmap.get(attr)
        if not maprange:
            return obj.NoneObject("Mask {0} not known".format(attr))

        bits = 2**maprange[1] - 1
        mask = bits << maprange[0]

        return self.v() & mask
    
class Enumeration(obj.NativeType):
    """Enumeration class for handling multiple possible meanings for a single value"""

    def __init__(self, targetType=None, offset=0, vm=None, parent=None,
                 choices=None, name=None, target="unsigned long",
                 **args):
        self.choices = {}
        if choices:
            self.choices = choices

        self.target = obj.Object(target, offset=offset, vm=vm, parent=parent)
        obj.NativeType.__init__(self, targetType, offset, vm, parent, **args)

    def v(self):
        return self.target.v()

    def __str__(self):
        value = self.v()
        if value in self.choices.keys():
            return self.choices[value]
        return 'Unknown choice ' + str(value)

    def __format__(self, formatspec):
        return format(self.__str__(), formatspec)