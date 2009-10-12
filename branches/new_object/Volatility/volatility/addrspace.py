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
"""

""" Alias for all address spaces """

#pylint: disable-msg=C0111

import os
import struct
import registry

import volatility.conf as conf
config = conf.ConfObject()

## By default load the profile that the user asked for
config.add_option("PROFILE", default='WinXPSP2',
                  help = "Name of the profile to load")

## Make sure the profiles are cached so we only parse it once. This is
## important since it allows one module to update the profile for
## another module.
PROFILES = {}

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

    def read(self, addr, len):
        """ Read some date from a certain offset """

    def get_available_addresses(self):
        """ Return a list of address ranges covered by this AS """

    def is_valid_address(self, addr):
        """ Tell us if the address is valid """
        return True
    
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
        if addr < self.base_offset or addr > self.base_offset + len(self.data):
            return False

        return True
        
    def read(self, addr, length):
        offset = addr - self.base_offset
        return self.data[offset: offset+length]
        
## Maintained for backward compatibility do not use in new code
class FileAddressSpace:
    def __init__(self, fname, mode='rb', fast=False):
        self.fname = fname
        self.name = fname
        self.fhandle = open(fname, mode)
        self.fsize = os.path.getsize(fname)

        if fast == True:
            self.fast_fhandle = open(fname, mode)

    def fread(self, len):
        return self.fast_fhandle.read(len)

    def read(self, addr, len):
        self.fhandle.seek(addr)        
        return self.fhandle.read(len)    

    def zread(self, addr, len):
        return self.read(addr, len)

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval, ) =  struct.unpack('=L', string)
        return longval

    def get_address_range(self):
        return [0, self.fsize-1]

    def get_available_addresses(self):
        return [0, self.get_address_range()]

    def is_valid_address(self, addr):
        if addr == None:
            return False
        return addr < self.fsize - 1

    def close(self):
        self.fhandle.close()
