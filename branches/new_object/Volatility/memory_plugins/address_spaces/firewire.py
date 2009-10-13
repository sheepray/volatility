'''
Created on 12 Oct 2009

@author: Mike Auty
'''

import urlparse
import volatility.addrspace as addrspace
import volatility.conf
config = volatility.conf.ConfObject()

class FirewireAddressSpace(addrspace.BaseAddressSpace):
    """A physical layer address space that provides access via firewire"""
    
    ## We should be *almost* the AS of last resort
    order = 99
    def __init__(self, base, layered=False, **kargs):
        addrspace.BaseAddressSpace.__init__(self, base, **kargs)
        assert base == None or layered, 'Must be first Address Space'
        try:
            (scheme, netloc, path, _, _, _) = urlparse.urlparse(config.LOCATION)
        except AttributeError:
            assert False, "Unable to parse %s as a URL" % config.LOCATION
            
        assert scheme == 'firewire', 'Not a firewire URN'
        bus = int(netloc)
        node = int(path)
        assert bus is not None and node is not None, 'Bus and Node must be specified'

        self._node = None
        try:
            h = firewire.Host()
            self._node = h[bus][node]
        except IndexError:
            assert False, "Firewire node " + str(node) + " on bus " + str(bus) + " was not accessible"
        
        # We have a list of exclusions because we know that trying to read anything in these sections
        # will cause the target machine to bluescreen
        self._exclusions = sorted([(0xa0000, 0xfffff, "Upper Memory Area")])
        
        self.name = "Firewire on Bus " + str(bus) + " Node " + str(node) 
        self.offset = 0
        # We have no way of knowing how big a firewire space is...
        # Set it to the maximum for the moment
        # TODO: Find a way of determining the size safely and reliably from the space itself 
        self.size = 0xFFFFFFFF

    def intervals(self, start, end):
        """Returns a list of intervals, from start to end, that do not include the exclusions"""
        return self._intervals(sorted(self._exclusions), start, end, [])

    def _intervals(self, exclusions, start, end, accumulator):
        """Accepts a sorted list of intervals and a start and end
        
           This will return a list of intervals between start and length
           that does not contain any of the intervals in the list of exclusions.
        """
        if not len(exclusions):
            # We're done
            return accumulator + [(start, end)]

        e = exclusions[0]
        estart = e[0]
        eend = e[1]
        
        # e and range overlap
        if not (eend < start or estart > end):
            # Ignore this exclusions
            return self.intervals(exclusions[1:], start, end, accumulator)
        if estart < start:
            if eend < end: 
                # Covers the start of the remaining length
                return self.intervals(exclusions[1:], eend, end, accumulator)
            else:
                # Covers the entire remaining area
                return accumulator
        else:
            if eend < end:
                # Covers a section of the remaining length
                return self.intervals(exclusions[1:], eend, end, accumulator + [(start, estart)])
            else:
                # Covers the end of the remaining length
                return accumulator + [(start, estart)]
            
    def read(self, offset, length):
        """Reads a specified size in bytes from the current offset
        
           Fills any excluded holes with zeros (so in that sense, similar to zread
        """
        ints = self.intervals(offset, offset + length)
        output = "\x00" * length
        for i in ints:
            output = output[: i[0] - self.offset] + self._node.read(i[1] - i[0], i[0]) + output[i[1] - self.offset:] 
        return output
    
    def get_address_range(self):
        """Returns the size of the address range"""
        return [0, self.size-1]

    def get_available_addresses(self):
        """Returns a list of available addresses"""
        return self.intervals(0, self.size)

try:
    import firewire
except ImportError:
    FirewireAddressSpace = None
