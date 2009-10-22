""" General debugging framework """
import volatility.conf
config = volatility.conf.ConfObject()

config.add_option("DEBUG", short_option='d', default = 0,
                  action = 'count',
                  help = "Debug volatility")

import pdb

def debug(msg, level=1):
    """Outputs a debugging message"""
    if config.DEBUG >= level:
        print msg

def b():
    """Enters the debugger at the call point"""
    pdb.set_trace()

def trace():
    """Enters the debugger at the call point"""
    pdb.set_trace()

def post_mortem():
    """Provides a command line interface to python after an exception's occurred"""
    pdb.post_mortem()
