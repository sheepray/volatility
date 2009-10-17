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
        except:
            pass
        
        ## length must be an integer
        obj.NativeType.__init__(self, theType, offset, vm, parent=parent, profile=profile,
                            name=name, format_string="%ds" % length)

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
    
    def __add__(self, other):
        """Set up mappings for concat"""
        return str(self) + other
    
    def __radd__(self, other):
        """Set up mappings for reverse concat"""
        return other + str(self)
