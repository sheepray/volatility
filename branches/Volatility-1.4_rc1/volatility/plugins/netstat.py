# Volatility
#
# Authors:
# Michael Hale Ligh <michael.hale@gmail.com>
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

import socket
import volatility.utils as utils
import volatility.obj as obj
import volatility.plugins.netscan as netscan

#--------------------------------------------------------------------------------
#                                   Netstat
#
# The tcpip!TcpPortPool and tcpip!UdpPortPool symbols point to a _PORTPOOL data 
# structure, which resides in a pool of type InPP (however due to size, there is 
# no corresponding _POOL_HEADER). The structure contains a bitmap composed of 
# 65536 bits (one bit for each port). To indicate that a given port is in use, 
# Windows uses RtlSetBit. In order to find the data structure that contains the 
# TCP and UDP fields for the port, we must use the array of 256 port assignment
# structures, which are also in the _PORTPOOL. 
#
# The TCP data structures found in the TcpPortPool can either be TcpL or TcpE. 
# For the purposes of this plugin, we only analyze the TcpL. For UDP structures
# we are looking at UdpA pools. 
#
# Note: Before we use this plugin, one of two things needs to happen:
#     1) Find the TcpPortPool and UdpPortPool symbols without using hard-coded offsets
#     2) Find them by scanning for InPP in the large pool table
#--------------------------------------------------------------------------------

netstat_types = {
    '_PORTPOOL': [ 0x10080, { # InPP but no tag
        'Resource': [ 0x0, ['_ERESOURCE']],
        'BitMapHeader': [ 0x50, ['_RTL_BITMAP']],
        'PortAssignment': [ 0x58, ['array', 256, ['pointer', ['_PORT_ASSIGNMENT']]]],
    } ],
    '_PORT_ASSIGNMENT' : [ 0x18, {
        'pData' : [ 0x14, ['pointer', ['void']]],
    } ],
    '_PORT_SUBENTRY' : [ None, {
        'pData' : [ 0x4, ['pointer', ['void']]],
    } ],
}

class Netstat(netscan.Netscan):
    "Traverse the IPv4 and IPv6 TCP and UDP sockets, using Bitmaps and Port Pools"

    def obj_from_bitmap(self, addr_space, offset):
        """Find out which ports are in use by scanning the Bitmap, and use that info 
        to derive the address of the corresponding TCP or UDP data structure"""
        PortPool = obj.Object('_PORTPOOL', offset, addr_space)
        port_bitmap = addr_space.zread(PortPool.BitMapHeader.Buffer, PortPool.BitMapHeader.SizeOfBitMap / 8)
        for cnt in xrange(1, len(port_bitmap) * 8):
            if ((ord(port_bitmap[cnt / 8]) & (1 << (cnt % 8))) != 0):
                offset = PortPool.PortAssignment[cnt >> 8].pData + ((cnt & 0xFF) * 8)
                yield obj.Object('_PORT_SUBENTRY', offset, addr_space)

    def calculate(self):
        addr_space = utils.load_as(self._config)
        addr_space.profile.add_types(netstat_types)

        TcpPortPool = 0x8504c000 # The address of tcpip!_TcpPortPool
        UdpPortPool = 0x8505d000 # The address of tcpip!_UdpPortPool

        # Chopping off the lower 3 bits (similar to _EX_FAST_REF) is done in InetBeginEnumeratePort. 
        # The subtraction is done in TcpEnumerateListeners and UdpEnumerateEndpoints.
        TcpMask = lambda x : (x & 0xFFFFFFFC) - 0x40
        UdpMask = lambda x : (x & 0xFFFFFFFC) - 0x4C

        for tcp in self.obj_from_bitmap(addr_space, TcpPortPool):

            # Determine if this is a TCP listener or TCP endpoint by looking at the tag
            tcp_address = TcpMask(tcp.pData.v())
            tag = addr_space.read(tcp_address - 4, 4)

            if tag == "TcpL":
                tcpentry = obj.Object('_TCP_LISTENER', tcp_address, addr_space)

                if tcpentry.AddressFamily & netscan.AF_INET:
                    # Lookup the TCP port 
                    lport = socket.ntohs(tcpentry.Port)

                    # For TcpL objects, the state is always listening and the remote port is zero
                    state = "LISTENING"
                    rport = 0

                    for ver, laddr, raddr, owner in self.enumerate_listeners(tcpentry, addr_space):
                        yield tcpentry.obj_offset, "TCP" + ver, laddr, lport, \
                            raddr, rport, state, owner, tcpentry.CreateTime

        for udp in self.obj_from_bitmap(addr_space, UdpPortPool):
            udpentry = obj.Object('_UDP_ENDPOINT', UdpMask(udp.pData.v()), addr_space)

            # Lookup the UDP port 
            lport = socket.ntohs(udpentry.Port)

            # For UdpA objects, the state is always blank and the remote end is asterisks
            state = ""
            raddr = rport = "*"

            for ver, laddr, _, owner in self.enumerate_listeners(udpentry, addr_space):
                yield udpentry.obj_offset, "UDP" + ver, laddr, lport, \
                    raddr, rport, state, owner, udpentry.CreateTime

