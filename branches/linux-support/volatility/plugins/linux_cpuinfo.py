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

"""
@author:       Andrew Case
@license:      GNU General Public License 2.0 or later
@contact:      atcuno@gmail.com
@organization: Digital Forensics Solutions
"""

import volatility.obj as obj

import linux_common

class linux_cpuinfo(linux_common.AbstractLinuxCommand):

    ''' prints info about each active processor '''

    def calculate(self):
    
        cpus = self.online_cpus()
    
        if len(cpus) > 1 and "per_cpu__cpu_info" in self.smap:
            func = self.get_info_smp
        
        elif "boot_cpu_data" in self.smap:
            func = self.get_info_single

        else:
            raise AttributeError, "Unable to get CPU info for memory capture"

        for i, cpu in func(cpus):
            yield i, cpu
       

    def bit_is_set(self, bmap, pos):

        mask = 1 << pos
        return bmap & mask

    def online_cpus(self):

        # later kernels..
        if "cpu_online_bits" in self.smap:
            bmap = obj.Object("unsigned long", offset=self.smap["cpu_online_bits"], vm=self.addr_space)

        elif "cpu_present_map" in self.smap:
            bmap = obj.Object("unsigned long",  offset=self.smap["cpu_present_map"], vm=self.addr_space)

        else:
            raise AttributeError, "Unable to determine number of online CPus for memory capture"

        cpus = []
        for i in xrange(0, 8):
            if self.bit_is_set(bmap, i):
                cpus.append(i)
            
        return cpus    
                         
    def get_info_single(self, cpus):
       
        cpu = obj.Object("cpuinfo_x86", offset=self.smap["boot_cpu_data"], vm=self.addr_space)

        yield 0, cpu

    # pulls the per_cpu cpu info
    # will break apart the per_cpu code if a future plugin needs it
    def get_info_smp(self, cpus):
     
        # get the highest numbered cpu
        max_cpu = cpus[-1]
 
        per_offsets = obj.Object(theType='Array', targetType='unsigned long', count=max_cpu, offset=self.smap["__per_cpu_offset"], vm=self.addr_space)

        i = 0
        for i in cpus:
            
            offset = per_offsets[i]

            addr = self.smap["per_cpu__cpu_info"] + offset.v()
            cpu = obj.Object("cpuinfo_x86", offset=addr, vm=self.addr_space)

            yield i, cpu

    def render_text(self, outfd, data):

        outfd.write("{0:12s} {1:16s} {2:64s}\n".format("Processor", "Vendor", "Model"))
        for i, cpu in data:
            outfd.write("{0:12s} {1:16s} {2:64s}\n".format(str(i), cpu.x86_vendor_id, cpu.x86_model_id))
       
