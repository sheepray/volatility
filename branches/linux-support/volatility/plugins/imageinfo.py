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

import volatility.win32.tasks as tasks
import volatility.timefmt as timefmt
import volatility.utils as utils
import volatility.obj as obj
import volatility.cache as cache
import volatility.registry as registry
import volatility.plugins.kdbgscan as kdbg

class ImageInfo(kdbg.KDBGScan):
    """ Identify information for the image """
    def __init__(self, config, args = None):
        kdbg.KDBGScan.__init__(self, config, args)

    def render_text(self, outfd, data):
        """Renders the calculated data as text to outfd"""
        for k, v in data:
            outfd.write("{0:>30} : {1}\n".format(k, v))

    @cache.CacheDecorator("tests/imageinfo")
    def calculate(self):
        """Calculates various information about the image"""
        print "Determining profile based on KDBG search...\n"
        profilelist = [ p.__name__ for p in registry.PROFILES.classes ]

        bestguess = None
        suglist = [ s for s, _ in kdbg.KDBGScan.calculate(self)]
        if suglist:
            bestguess = suglist[0]
        suggestion = ", ".join(suglist)

        # Set our suggested profile first, then run through the list
        if bestguess in profilelist:
            profilelist = [bestguess] + profilelist
        chosen = 'no profile'
        for profile in profilelist:
            self._config.update('PROFILE', profile)
            addr_space = utils.load_as(self._config)
            if hasattr(addr_space, "dtb"):
                chosen = profile
                break

        if bestguess != chosen:
            suggestion += ' (Instantiated with ' + chosen + ')'

        yield ('Suggested Profile(s)', suggestion)

        tmpas = addr_space
        count = 0
        while tmpas:
            count += 1
            yield ('AS Layer' + str(count), tmpas.__class__.__name__ + " (" + tmpas.name + ")")
            tmpas = tmpas.base

        if not hasattr(addr_space, "pae"):
            yield ('PAE type', "PAE")
        else:
            yield ('PAE type', "No PAE")

        if hasattr(addr_space, "dtb"):
            yield ('DTB', hex(addr_space.dtb))

        volmagic = obj.Object('VOLATILITY_MAGIC', 0x0, addr_space)
        kpcroffset = None
        if hasattr(addr_space, "dtb"):
            kdbgoffset = volmagic.KDBG.v()
            yield ('KDBG', hex(kdbgoffset))

            kpcroffset = volmagic.KPCR.v()
            yield ('KPCR', hex(kpcroffset))
            if kpcroffset:
                KUSER_SHARED_DATA = volmagic.KUSER_SHARED_DATA.v()
                yield ('KUSER_SHARED_DATA', hex(KUSER_SHARED_DATA))

                data = self.get_image_time(addr_space)

                yield ('Image date and time', data['ImageDatetime'])
                yield ('Image local date and time', timefmt.display_datetime(data['ImageDatetime'].as_datetime(), data['ImageTz']))

        try:
            yield ('Image Type', self.find_csdversion(addr_space))
        except tasks.TasksNotFound:
            pass

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

    def find_csdversion(self, addr_space):
        """Find the CDS version from an address space"""
        csdvers = {}
        for task in tasks.pslist(addr_space):
            if task.Peb.CSDVersion:
                lookup = str(task.Peb.CSDVersion)
                csdvers[lookup] = csdvers.get(lookup, 0) + 1
                _, result = max([(v, k) for k, v in csdvers.items()])

                return str(result)

        return obj.NoneObject("Unable to find version")
