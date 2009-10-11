""" General debugging framework """
import forensics.conf
config = forensics.conf.ConfObject()
config.add_option("DEBUG", short_option='d', default = False,
                  action = 'store_true',
                  help = "Debug this build")

import pdb

def debug(msg, level=1):
    if config.DEBUG >= level:
        print msg

def b():
    pdb.set_trace()

def trace():
    pdb.set_trace()
