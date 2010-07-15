# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Original Source:
# Copyright (C) 2004,2005,2006 4tphi Research
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

   Alias for all address spaces 

"""

#pylint: disable-msg=C0111

import registry

import volatility.conf as conf
config = conf.ConfObject()

## By default load the profile that the user asked for
config.add_option("PROFILE", default='WinXPSP2',
                  help = "Name of the profile to load")

config.add_option("LOCATION", default=None, short_option='l',
                  help = "A URN location from which to load an address space")

## Make sure the profiles are cached so we only parse it once. This is
## important since it allows one module to update the profile for
## another module.
PROFILES = {}

class ASAssertionError(AssertionError):
    
    def __init__(self, *args, **kwargs):
        AssertionError.__init__(self, *args, **kwargs)

class BaseAddressSpace:
    """ This is the base class of all Address Spaces. """
    def __init__(self, base, **kwargs):
        """ base is the AS we will be stacking on top of, opts are
        options which we may use.
        """
        self.base = base
        ## Load the required profile
        try:
            self.profile = PROFILES[config.PROFILE]
        except KeyError:
            self.profile = registry.PROFILES[config.PROFILE]()
            PROFILES[config.PROFILE] = self.profile

    def as_assert(self, assertion, error = None):
        """Duplicate for the assert command (so that optimizations don't disable them)
        
           It had to be called as_assert, since assert is a keyword
        """
        if not assertion:
            if error == None:
                error = "Instantiation failed for unspecified reason"
            raise ASAssertionError, error

    def read(self, addr, length):
        """ Read some date from a certain offset """

    def get_available_addresses(self):
        """ Return a generator of address ranges covered by this AS """
        raise StopIteration

    def is_valid_address(self, _addr):
        """ Tell us if the address is valid """
        return True
    
    def write(self, _addr, _buf):
        if not config.WRITE:
            return False
        raise NotImplementedError("Write support for this type of Address Space has not been implemented")
    
## This is a specialised AS for use internally - Its used to provide
## transparent support for a string buffer so types can be
## instantiated off the buffer.
class BufferAddressSpace(BaseAddressSpace):
    def __init__(self, base_offset = 0, data = '', **kwargs):
        BaseAddressSpace.__init__(self, None, **kwargs)
        self.fname = "Buffer"
        self.data = data
        self.base_offset = base_offset

    def assign_buffer(self, data, base_offset=0):
        self.base_offset = base_offset
        self.data = data

    def is_valid_address(self, addr):
        return not (addr < self.base_offset or addr > self.base_offset + len(self.data))
        
    def read(self, addr, length):
        offset = addr - self.base_offset
        return self.data[offset: offset+length]
    
    def write(self, addr, data):
        if not config.WRITE:
            return False
        self.data = self.data[:addr] + data + self.data[addr + len(data):]
        return True