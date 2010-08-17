# Volatility
#
# Authors:
# Mike Auty <mike.auty@gmail.com>
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

#pylint: disable-msg=C0111

import volatility.commands as commands
import volatility.win32.network as network
import volatility.utils as utils

class Connections(commands.command):
    """
    Print list of open connections
    ------------------------------

    This module follows the handle table of each task and prints
    current connections.

    Note that if you are using a hibernated image this might not work
    because Windows closes all sockets before hibernating. You might
    find it more effective to do conscan instead.
    """

    def __init__(self, args = None):
        commands.command.__init__(self, args)

    def render_text(self, outfd, data):
        if len(data):
            outfd.write("{0:25} {1:25} {2:6}\n".format('Local Address', 'Remote Address', 'Pid'))

        for conn in data:
            local = "{0}:{1}".format(conn.LocalIpAddress, conn.LocalPort)
            remote = "{0}:{1}".format(conn.RemoteIpAddress, conn.RemotePort)
            outfd.write("{0:25} {1:25} {2:6}\n".format(local, remote, conn.Pid))


    def calculate(self):
        addr_space = utils.load_as()

        result = network.determine_connections(addr_space)

        return result
