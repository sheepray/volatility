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

""" General debugging framework """
import volatility.conf
config = volatility.conf.ConfObject()

config.add_option("DEBUG", short_option = 'd', default = 0,
                  action = 'count',
                  help = "Debug volatility")

import pdb

def debug(msg, level = 1):
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
    if config.DEBUG:
      pdb.post_mortem()
