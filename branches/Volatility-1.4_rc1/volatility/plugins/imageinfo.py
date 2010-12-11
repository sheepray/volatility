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
import volatility.scan as scan
import volatility.addrspace as addrspace
import volatility.registry as registry
import volatility.plugins.datetime as datetime

class MultiStringFinderCheck(scan.ScannerCheck):
    def __init__(self, address_space, needles = None):
        scan.ScannerCheck.__init__(self, address_space)
        if not needles:
            needles = []
        self.needles = needles
        self.maxlen = 0
        for needle in needles:
            self.maxlen = max(self.maxlen, len(needle))
        if not self.maxlen:
            raise RuntimeError("No needles of any length were found for the MultiStringFinderCheck")

    def check(self, offset):
        verify = self.address_space.read(offset, self.maxlen)
        for match in self.needles:
            if verify[:len(match)] == match:
                return True
        return False

    def skip(self, data, offset):
        nextval = len(data)
        for needle in self.needles:
            dindex = data.find(needle, offset + 1)
            if dindex > -1:
                nextval = min(nextval, dindex)
        return nextval - offset

class KDBGScanner(scan.DiscontigScanner):
    checks = [ ]

    def __init__(self, window_size = 8, needles = None):
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.DiscontigScanner.__init__(self, window_size)

class ImageInfo(datetime.DateTime):
    """ Identify information for the image """
    def __init__(self, config, args = None):
        datetime.DateTime.__init__(self, config, args)

    def render_text(self, outfd, data):
        """Renders the calculated data as text to outfd"""
        for k, v in data:
            outfd.write("{0:>30} : {1}\n".format(k, v))

    def suggest_profile(self, profilelist):
        """Does a scan of the physical address space, looking for a KDBG header"""

        proflens = {}
        maxlen = 0
        for p in profilelist:
            self._config.update('PROFILE', p)
            buf = addrspace.BufferAddressSpace(self._config)
            volmag = obj.Object('VOLATILITY_MAGIC', offset = 0, vm = buf)
            proflens[p] = str(volmag.KDBGHeader)
            maxlen = max(maxlen, len(proflens[p]))

        proflens.update({'WinXPSP0x64':'\x00\xf8\xff\xffKDBG\x90\x02',
                         'Win7SP0x64':'\x00\xf8\xff\xffKDBG\x40\x03',
                         'Win2003SP0x64':'\x00\xf8\xff\xffKDBG\x18\x03',
                         'Win2003SP0x86':'\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x18\x03',
                         'Win2008SP0x64':'\x00\xf8\xff\xffKDBG\x30\x03',
                         'Win2008SP0x86':'\x00\x00\x00\x00\x00\x00\x00\x00KDBG\x30\x03',
                         'VistaSP0x64':'\x00\xf8\xff\xffKDBG\x28\x03'})

        scanner = KDBGScanner(needles = proflens.values())

        flat = utils.load_as(self._config, astype = 'physical')

        for offset in scanner.scan(flat):
            val = flat.read(offset, maxlen)
            for l in proflens:
                if proflens[l] == val[:len(proflens[l])]:
                    return l

        #XP = '\x90\x02'
        #vista = '\x28\x03'
        #win7 = '\x40\x03'
        #w2k3 = '\x18\x03'
        #w2k8 = '\x30\x03'

        return None

    def calculate(self):
        """Calculates various information about the image"""
        print "Determining profile based on KDBG search..."
        profilelist = [ p.__name__ for p in registry.PROFILES.classes ]

        suggestion = self.suggest_profile(profilelist)

        # Set our suggested profile first, then run through the list
        if suggestion in profilelist:
            profilelist = [suggestion] + profilelist
        chosen = 'None'
        for profile in profilelist:
            self._config.update('PROFILE', profile)
            addr_space = utils.load_as(self._config)
            if hasattr(addr_space, "dtb"):
                chosen = profile
                break

        if suggestion != chosen:
            suggestion += ' (Instantiated as ' + chosen + ')'

        yield ('Suggested Profile', suggestion)

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
