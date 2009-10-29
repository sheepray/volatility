'''
Created on 13 Oct 2009

@author: Mike Auty
'''

import volatility.conf as conf
import urlparse
import os
## This is required to ensure that LOCATION is defined here
import volatility.addrspace as addrspace #pylint: disable-msg=W0611

config = conf.ConfObject()

def set_location(_option, _opt_str, value, parser):
    """Sets the location variable in the parser to the filename in question"""
    if parser.values.location == None:
        parser.values.location = urlparse.urlunparse(('file', '', os.path.abspath(value), '', '', ''))

config.add_option("FILENAME", default = None, action="callback",
                  callback = set_location, type='str',
                  short_option = 'f', nargs = 1,
                  help = "Filename to use when opening an image")
