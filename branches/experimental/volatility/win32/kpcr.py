# Volatility
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

"""
@author:       Bradley Schatz 
@license:      GNU General Public License 2.0 or later
@contact:      bradley@schatzforensic.com.au
@organization: Schatz Forensic
"""

import volatility.obj as obj
import volatility.conf as conf
config = conf.ConfObject()

#
# Background to the technique used in this file can be found in 
# Damien Aumaitre (2009) "A little journey inside Windows memory", 
#

config.add_option('KPCR', short_option = 'k', default = None, type = 'int',
                  help = "Specify a specific KPCR address")

def get_kpcrobj(addr_space):
    ## Locate the kpcr struct - either hard coded or specified by the command line
    volmagic = obj.Object('VOLATILITY_MAGIC', 0x0, addr_space)
    kpcra = config.KPCR or volmagic.KPCR.v()

    return obj.Object("_KPCR",
                      offset = kpcra,
                      vm = addr_space)
