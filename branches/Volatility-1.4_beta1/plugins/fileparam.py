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

config.add_option("FILENAME", default = None,
                  short_option = 'f',
                  help = "Filename to use when opening an image")

## Check if that has been set - we parse all options just in
## case. Note that it might be possible for options to be set after
## invalid options and we wont see them here. For example say --foobar
## is defined in a plugin which has not been loaded yet, and the argvs
## look like:

## volatility.py --foobar --filename XXXX

## We will not see filename here because parsing will stop until the
## foobar has been defined.

## The proper solution to this is to come up with an Event system like
## in PyFlag where events can be emitted at different points in the
## startup process.
config.parse_options(final=False)

if config.FILENAME and not config.LOCATION:
    config.update('LOCATION', urlparse.urlunparse(
        ('file', '', os.path.abspath(config.FILENAME), '', '', '')))
