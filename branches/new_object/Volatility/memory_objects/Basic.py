""" This file defines some basic types which might be useful for many
OS's
"""
# FIXME: It's currently important these are imported here, otherwise
# they don't show up in the MemoryObjects registry
from forensics.object2 import BitField, Pointer, Void, Array, CType
import forensics.object2 as object2

class String(object2.NativeType):
    def __init__(self, type, offset, vm=None,
                 length=1, parent=None, profile=None, name=None, **args):
        ## Allow length to be a callable:
        try:
            length = length(parent)
        except:
            pass
        
        ## length must be an integer
        object2.NativeType.__init__(self, type, offset, vm, parent=parent, profile=profile,
                            name=name, format_string="%ds" % length)

    def upper(self):
        return self.__str__().upper()

    def lower(self):
        return self.__str__().lower()

    def __str__(self):
        data = self.v()
        ## Make sure its null terminated:
        return data.split("\x00")[0]
