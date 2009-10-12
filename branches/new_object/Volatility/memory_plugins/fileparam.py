'''
Created on 13 Oct 2009

@author: Mike Auty
'''

import volatility.conf as conf
import urlparse
import os

config = conf.ConfObject()

config.add_option("FILENAME", default = None,
                  short_option = 'f',
                  help = "Filename to use when opening an image")

if config.FILENAME is not None:
    if config.LOCATION is None:
        config.update('LOCATION', urlparse.urlunparse(('file', '', os.path.abspath(config.FILENAME), '', '', '')))