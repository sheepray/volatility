# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Derived from source in PyFlag developed by:
# Copyright 2004: Commonwealth of Australia.
# Michael Cohen <scudette@users.sourceforge.net> 
# David Collett <daveco@users.sourceforge.net>
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
#
# Special thanks to Michael Cohen for ideas and comments!
#

#pylint: disable-msg=C0111

"""
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems.
"""
import volatility.debug as debug
import volatility.registry as registry
import volatility.addrspace as addrspace

BLOCKSIZE = 1024*1024*10

########### Following is the new implementation of the scanning
########### framework. The old framework was based on PyFlag's
########### scanning framework which is probably too complex for this.

class BaseScanner(object):
    """ A more thorough scanner which checks every byte """
    checks = []
    def __init__(self, window_size=8):
        self.buffer = addrspace.BufferAddressSpace(data='\x00'*1024)
        self.window_size = window_size
        self.constraints = []
        
        ## Build our constraints from the specified ScannerCheck
        ## classes:
        for class_name, args in self.checks:
            check = registry.SCANNER_CHECKS[class_name](self.buffer, **args)
            self.constraints.append(check)
            
        self.base_offset = None
        self.error_count = 0

    def check_addr(self, found):
        """ This calls all our constraints on the offset found and
        returns the number of contrainst that matched.

        We shortcut the loop as soon as its obvious that there will
        not be sufficient matches to fit the criteria. This allows for
        an early exit and a speed boostup.
        """
        cnt = 0
        for check in self.constraints:
            ## constraints can raise for an error
            try:
                val = check.check(found)
            except Exception:
                debug.b()
                val = False
            
            if not val:
                cnt = cnt+1

            if cnt > self.error_count:
                return False
            
        return True

    def scan(self, address_space):
        self.base_offset = 0
        ## Which checks also have skippers?
        skippers = [ c for c in self.constraints if hasattr(c, "skip") ]
        while 1:
            data = address_space.read(self.base_offset, BLOCKSIZE)
            if not data:
                break
            
            self.buffer.assign_buffer(data, self.base_offset)
            i = 0
            ## Find all occurances of the pool tag in this buffer and
            ## check them:
            while i < len(data):
                if self.check_addr(i + self.base_offset):
                    ## yield the offset to the start of the memory
                    ## (after the pool tag)
                    yield i + self.base_offset

                ## Where should we go next? By default we go 1 byte
                ## ahead, but if some of the checkers have skippers,
                ## we may actually go much farther. Checkers with
                ## skippers basically tell us that there is no way
                ## they can match anything before the skipped result,
                ## so there is no point in trying them on all the data
                ## in between. This optimization is useful to really
                ## speed things up. FIXME - currently skippers assume
                ## that the check must match, therefore we can skip
                ## the unmatchable region, but its possible that a
                ## scanner needs to match only some checkers.
                skip = 1
                for s in skippers:
                    skip = max(skip, s.skip(data, i))

                i += skip

            self.base_offset += len(data)


class ScannerCheck(object):
    """ A scanner check is a special class which is invoked on an AS to check for a specific condition.

    The main method is def check(self, offset):
    This will return True if the condition is true or False otherwise.

    This class is the base class for all checks.
    """
    def __init__(self, address_space, **kwargs):
        self.address_space = address_space

    def object_offset(self, offset):
        return offset

    def check(self, offset):
        return False

    ## If you want to speed up the scanning define this method - it
    ## will be used to skip the data which is obviously not going to
    ## match. You will need to return the number of bytes from offset
    ## to skip to. We take the maximum number of bytes to guarantee
    ## that all checks have a chance of passing.
    #def skip(self, data, offset):
    #    return -1

class PoolScanner(BaseScanner):
    ## These are the objects that follow the pool tags
    preamble = [ '_POOL_HEADER', ]
    
    def object_offset(self, found):
        """ This returns the offset of the object contained within
        this pool allocation.
        """
        return found + sum([self.buffer.profile.get_obj_size(c) for c in self.preamble]) - 4

    def scan(self, address_space):
        for i in BaseScanner.scan(self, address_space):
            yield self.object_offset(i)
