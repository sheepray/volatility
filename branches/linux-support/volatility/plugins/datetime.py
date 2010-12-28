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

import volatility.timefmt as timefmt
import volatility.obj as obj
import volatility.utils as utils
import volatility.commands as commands

#pylint: disable-msg=C0111

class DateTime(commands.command):
    """Get date/time information for image"""
    def render_text(self, outfd, data):
        """Renders the calculated data as text to outfd"""
        dt = data['ImageDatetime'].as_datetime()

        outfd.write("Image date and time       : {0}\n".format(data['ImageDatetime']))
        outfd.write("Image local date and time : {0}\n".format(timefmt.display_datetime(dt, data['ImageTz'])))

    def calculate(self):
        addr_space = utils.load_as(self._config)

        return self.get_image_time(addr_space)

    def get_image_time(self, addr_space):
        # Get the Image Datetime
        result = {}
        volmagic = obj.Object("VOLATILITY_MAGIC", 0x0, addr_space)
        KUSER_SHARED_DATA = volmagic.KUSER_SHARED_DATA.v()
        k = obj.Object("_KUSER_SHARED_DATA",
                              offset = KUSER_SHARED_DATA,
                              vm = addr_space)

        result['ImageDatetime'] = k.SystemTime
        result['ImageTz'] = timefmt.OffsetTzInfo(-k.TimeZoneBias.as_windows_timestamp() / 10000000)

        return result
