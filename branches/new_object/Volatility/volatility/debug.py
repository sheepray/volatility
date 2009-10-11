""" General debugging framework """
import volatility.conf
config = volatility.conf.ConfObject()

config.add_option("DEBUG", short_option='d', default = 0,
                  action = 'count',
                  help = "Debug volatility")

import pdb

def debug(msg, level=1):
    if config.DEBUG >= level:
        print msg

def b():
    pdb.set_trace()

def trace():
    pdb.set_trace()

def post_mortem():
    pdb.post_mortem(t = sys.exc_info()[2])
