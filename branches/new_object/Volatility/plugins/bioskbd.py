'''
Created on 3 Oct 2009

@author: Mike Auty

*Heavily* based upon http://www.storm.net.nz/static/files/bioskbsnarf
'''

import struct
import volatility.commands as commands
import volatility.utils as utils
import volatility.conf as conf
config = conf.ConfObject()

class bioskbd(commands.command):
    """Reads the keyboard buffer from Real Mode memory"""
    BASE = 0x400
    OFFSET = 0x17
    BUFOFFSET = 0x1e
    LEN = 39
    FORMAT = "<BBBHH32s"
    
    def render_text(self, outfd, data):
        """Displays the character codes"""
        outfd.write("Ascii     Scancode\n")
        for c, s in data:
            outfd.write("%c (0x%02x)   0x%02x\n" % (self.format_char(c), ord(c), s))
    
    def format_char(self, c):
        """Prints out an ascii printable character"""
        if c in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]{};\'#:@~,./<>?!"$%^&*()_+-=`\\|':
            return c
        return "." 
    
    def calculate(self):
        """Calculate returns the results of the bios keyboard reading"""
        addr_space = utils.load_as(astype = 'physical')
        data = addr_space.read(self.BASE + self.OFFSET, self.LEN)
        if not data or len(data) != self.LEN:
            config.error("Failed to read keyboard buffer, please check this is a physical memory image.")
        _shifta, _shiftb, _alt, readp, _writep, buf = struct.unpack(self.FORMAT, data)
        unringed = buf[readp - self.BUFOFFSET:]
        unringed += buf[:readp - self.BUFOFFSET]
        results = []
        for i in range(0, len(unringed)-2, 2):
            if ord(unringed[i]) != 0:
                results.append((unringed[i], ord(unringed[i+1])))
        
        return results
