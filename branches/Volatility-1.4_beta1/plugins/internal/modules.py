'''
Created on 25 Sep 2009

@author: Mike Auty
'''

#pylint: disable-msg=C0111

import volatility.commands
import volatility.win32 as win32
import volatility.utils as utils

class modules(volatility.commands.command):
    """Print list of loaded modules"""
    def render_text(self, outfd, data):
        header = False
        
        for module in data:
            if not header:
                outfd.write("{0:50} {1:12} {2:8} {3}\n".format('File', 'Base', 'Size', 'Name'))
                header = True
            outfd.write("{0:50} 0x{1:010x} 0x{2:06x} {3}\n".format(module.FullDllName, module.BaseAddress, module.SizeOfImage, module.ModuleName))

    def calculate(self):
        addr_space = utils.load_as()
        
        result = win32.modules.lsmod(addr_space)

        return result
