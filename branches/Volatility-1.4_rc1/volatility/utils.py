# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

import volatility.registry as registry
import volatility.addrspace as addrspace
import volatility.conf as conf
config = conf.ConfObject()
import volatility.debug as debug

#pylint: disable-msg=C0111

def load_as(**kwargs):
    base_as = None
    error = AddrSpaceError()
    while 1:
        debug.debug("Voting round")
        found = False
        for cls in registry.AS_CLASSES.classes:
            debug.debug("Trying {0} ".format(cls))
            try:
                base_as = cls(base_as, **kwargs)
                debug.debug("Succeeded instantiating {0}".format(base_as))
                found = True
                break
            except addrspace.ASAssertionError, e:
                debug.debug("Failed instantiating {0}: {1}".format(cls.__name__, e), 2) 
                error.append_reason(cls.__name__, e) 
                continue
            except Exception, e:
                debug.debug("Failed instantiating %s" % e) 
                continue               

        ## A full iteration through all the classes without anyone
        ## selecting us means we are done:
        if not found:
            break

    if base_as is None:
        raise error

    return base_as

class AddrSpaceError(Exception):
    """Address Space Exception, so we can catch and deal with it in the main program"""
    def __init__(self):
        self.reasons = []
        Exception.__init__(self, "No suitable address space mapping found")
    
    def append_reason(self, driver, reason):
        self.reasons.append((driver, reason))

    def __str__(self):
        result = Exception.__str__(self) + "\nTried to open image as:\n"
        for k, v in self.reasons:
            result += " {0}: {1}\n".format(k, v)

        return result
