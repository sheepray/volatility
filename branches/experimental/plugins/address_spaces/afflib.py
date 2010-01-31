""" This address space allows us to open aff file """
import standard
import volatility.debug as debug
import volatility.addrspace as addrspace

from ctypes import *
import ctypes.util
import volatility.conf
config = volatility.conf.ConfObject()

possible_names = ['afflib',]
for name in possible_names:
    resolved = ctypes.util.find_library(name)
    if resolved:
        break

try:
    if resolved == None:
        raise ImportError("afflib not found")
    afflib = CDLL(resolved)
    if not afflib._name: raise OSError()
except OSError:
    raise ImportError("afflib not found")

class afffile:
    """ A file like object to provide access to the aff file """
    def __init__(self, volume):
        self.handle = afflib.af_open(volume, c_int(0),
                                     c_int(0))
        if self.handle==0:
            raise RuntimeError("Unable to open aff file")

        self.readptr = 0
        self.size = afflib.af_get_imagesize(self.handle)

    def seek(self, offset, whence=0):
        if whence==0:
            self.readptr = offset
        elif whence==1:
            self.readptr += offset
        elif whence==2:
            self.readptr = self.size + offset

        self.readptr = min(self.readptr, self.size)

    def tell(self):
        return self.readptr

    def read(self, length):
        buf = create_string_buffer(length)
        afflib.af_seek(self.handle, c_ulonglong(self.readptr), 0)
        length = afflib.af_read(self.handle, buf,
                                c_ulong(length))

        return buf.raw[:length]

    def close(self):
        afflib.af_close(self.handle)
        self.handle = None
        
    def get_headers(self):
        afflib.af_rewind_seg(self.handle)
        result = {}
        while 1:
        ## Iterate over all segments and print those which are not pages
            segname = create_string_buffer(1024)
            segname_length = pointer(c_ulong(1024))

            data = create_string_buffer(1024)
            data_len = pointer(c_ulong(1024))

            res = afflib.af_get_next_seg(self.handle, segname, segname_length,
                                         c_ulong(0), data, data_len)
            if res==-2:
                afflib.af_get_next_seg(self.handle, segname, segname_length,
                                       c_ulong(0), c_ulong(0), c_ulong(0))
            elif res==0:
                key = segname.value
                if not key.startswith('page'):
                    result[segname.value] = data.value
            else:
                break

        return result


def aff_open(volumes):
    return afffile(volumes)

class AFFAddressSpace(standard.FileAddressSpace):
    """ An AFFLIB capable address space.

    In order for us to work we need:
    1) There must be a base AS.
    2) The first 7 bytes must be 41 46 46 31 30 0D 0A (AFF10 header)
    """
    order = 21
    def __init__(self, base, **kwargs):
        addrspace.BaseAddressSpace.__init__(self, base, **kwargs)
        assert(base)
        assert(base.read(0, 7) == "\x41\x46\x46\x31\x30\x0D\x0A")
        self.fhandle = aff_open(base.name)
        self.fhandle.seek(0, 2)
        self.fsize = self.fhandle.tell()
        self.fhandle.seek(0)

    def is_valid_address(self, addr):
        return True

    def write(self, _addr, _buf):
        if not config.WRITE:
            return False
        raise NotImplementedError("Write support is not implemented for AFF files")

if not afflib:
    del AFFAddressSpace
