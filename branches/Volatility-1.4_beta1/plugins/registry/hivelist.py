# Volatility
# Copyright (C) 2008 Volatile Systems
# Copyright (c) 2008 Brendan Dolan-Gavitt <bdolangavitt@wesleyan.edu>
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
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import hivescan as hs
import volatility.obj as obj
import volatility.utils as utils
import volatility.conf as conf
config = conf.ConfObject()

class hivelist(hs.hivescan):
    """Print list of registry hives.

    You must supply this module the initial offset of the hive. You
    can obtain this by running the hivescan module first.
    """
    # Declare meta information associated with this plugin
    
    meta_info = {}
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def __init__(self, *args):
        config.add_option("HIVE-OFFSET", short_option='o',
                          default = None, type='int',
                          help = "Offset to registry hive")
        
        hs.hivescan.__init__(self, *args)

    def render_text(self, outfd, result):
        outfd.write("Address      Name\n")

        for hive in result:
            name = hive.FileFullPath.v() or "[no name]"
            outfd.write("{0:#X}  {1}\n".format(hive.offset, name))
    
    def calculate(self):
        flat = utils.load_as(astype = 'physical')
        addr_space = utils.load_as()

        hives = hs.hivescan.calculate(self)

        if config.HIVE_OFFSET:
            hives = [config.HIVE_OFFSET]

        def generate_results():
            ## The first hive is normally given in physical address space
            ## - so we instantiate it using the flat address space. We
            ## then read the Flink of the list to locate the address of
            ## the first hive in virtual address space. hmm I wish we
            ## could go from physical to virtual memroy easier.
            for offset in hives:
                hive = obj.Object("_CMHIVE", int(offset), flat)
                if hive.HiveList.Flink.v():
                    start_hive_offset = hive.HiveList.Flink.v() - 0x224
    
                    ## Now instantiate the first hive in virtual address space as normal
                    start_hive = obj.Object("_CMHIVE", start_hive_offset, addr_space)
    
                    for hive in start_hive.HiveList:
                        yield hive

        return generate_results()

