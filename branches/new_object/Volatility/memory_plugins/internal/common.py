""" This plugin contains CORE classes used by lots of other plugins """
from forensics.win32.scan2 import ScannerCheck
from forensics.object2 import NewObject
import forensics.debug as debug

#pylint: disable-msg=C0111

## The following are checks for pool scanners.

class PoolTagCheck(ScannerCheck):
    """ This scanner checks for the occurance of a pool tag """
    def __init__(self, address_space, tag=None, **kwargs):
        self.tag = tag
        self.address_space = address_space

    def skip(self, data, offset):
        try:
            next = data.index(self.tag, offset+1)
            return next - offset
        except ValueError:
            ## Substring is not found - skip to the end of this data buffer
            return len(data) - offset

    def check(self, offset):
        data = self.address_space.read(offset, len(self.tag))
        return data == self.tag

class CheckPoolSize(ScannerCheck):
    """ Check pool block size """
    def __init__(self, address_space, condition=lambda x: x==8, **kwargs):
        self.condition = condition
        self.address_space = address_space

    def check(self, offset):
        pool_hdr = NewObject('_POOL_HEADER', vm=self.address_space,
                             offset = offset - 4)
        
        block_size = pool_hdr.BlockSize.v()
        
        return self.condition(block_size * 8)

class CheckPoolType(ScannerCheck):
    """ Check the pool type """
    def __init__(self, address_space, paged = False,
                 non_paged = False, free = False, **kwargs):
        self.non_paged = non_paged
        self.paged = paged
        self.free = free
        self.address_space = address_space

    def check(self, offset):
        pool_hdr = NewObject('_POOL_HEADER', vm=self.address_space,
                             offset = offset - 4)
        
        ptype = pool_hdr.PoolType.v()

        if self.non_paged and (ptype % 2) == 1:
            return True

        if self.free and ptype == 0:
            return True

        if self.paged and (ptype % 2) == 0 and ptype > 0:
            return True

class CheckPoolIndex(ScannerCheck):
    """ Checks the pool index """
    def __init__(self, address_space, value=0, **kwargs):
        self.value = value
        self.address_space = address_space

    def check(self, offset):
        pool_hdr = NewObject('_POOL_HEADER', vm=self.address_space,
                             offset = offset - 4)

        return pool_hdr.PoolIndex == self.value
