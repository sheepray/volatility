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
import volatility.protos as protos

import linux_flags
import linux_list_open_files as lsof

import socket

class linux_netstat(lsof.linux_lsof):
    ''' lists open files '''

    def calculate(self):

        if not self.profile.has_type("inet_sock"):
            # ancient (2.6.9) centos kernels do not have inet_sock in debug info
            raise AttributeError, "Given profile does not have inet_sock, please file a bug if the kernel version is > 2.6.11"

        openfiles = lsof.linux_lsof.calculate(self)

        for (task, filp, _i) in openfiles:

            # its a socket!
            if filp.f_op == self.smap["socket_file_ops"] or filp.get_dentry().d_op == self.smap["sockfs_dentry_operations"]:

                iaddr = filp.get_dentry().d_inode
                skt = self.SOCKET_I(iaddr)
                inet_sock = obj.Object("inet_sock", offset = skt.sk, vm = self.addr_space)

                yield task, inet_sock

    def render_text(self, outfd, data):

        for task, inet_sock in data:

            proto = self.get_proto_str(inet_sock)

            if proto in ("TCP", "UDP", "IP"):

                state = self.get_state_str(inet_sock) if proto == "TCP" else ""
                family = inet_sock.sk.__sk_common.skc_family #pylint: disable-msg=W0212

                if family == socket.AF_UNIX:

                    unix_sock = obj.Object("unix_sock", offset = inet_sock.sk.v(), vm = self.addr_space)

                    if unix_sock.addr:

                        name = obj.Object("sockaddr_un", offset = unix_sock.addr.name.obj_offset, vm = self.addr_space)

                        # only print out sockets with paths
                        if name.sun_path != "":
                            outfd.write("UNIX {0:s}\n".format(name.sun_path))

                elif family in (socket.AF_INET, socket.AF_INET6):

                    if family == socket.AF_INET:
                        (daddr, saddr) = self.format_ipv4(inet_sock)
                        (dport, sport) = self.format_port(inet_sock)

                    elif family == socket.AF_INET6:
                        (daddr, saddr) = self.format_ipv6(inet_sock)
                        (dport, sport) = self.format_port(inet_sock)

                    outfd.write("{0:8s} {1}:{2:<5} {3}:{4:<5} {5:s} {6:>17s}/{7:<5d}\n".format(proto, saddr, sport, daddr, dport, state, task.comm, task.pid))


    def format_ipv6(self, inet_sock):
        daddr = inet_sock.pinet6.daddr
        saddr = inet_sock.pinet6.saddr

        return (daddr.cast('Ipv6Address'), saddr.cast('Ipv6Address'))

    # formats an ipv4 address
    def format_ipv4(self, inet_sock):
        if hasattr(inet_sock, 'daddr') and inet_sock.daddr:
            daddr = inet_sock.daddr
            saddr = inet_sock.rcv_saddr
        else:
            daddr = inet_sock.inet_daddr
            saddr = inet_sock.inet_rcv_saddr

        return (daddr.cast('IpAddress'), saddr.cast('IpAddress').v())

    def format_port(self, inet_sock):
        if hasattr(inet_sock, 'dport'):
            dport = socket.htons(inet_sock.dport)
            sport = socket.htons(inet_sock.sport)
        else:
            dport = socket.htons(inet_sock.inet_dport)
            sport = socket.htons(inet_sock.inet_sport)

        return (dport, sport)

    def get_state_str(self, inet_sock):

        state = inet_sock.sk.__sk_common.skc_state #pylint: disable-msg=W0212

        return linux_flags.tcp_states[state]

    def get_proto_str(self, inet_sock):

        proto = inet_sock.sk.sk_protocol.v()

        return protos.protos.get(proto, 'UNKNOWN')

    # has to get the struct socket given an inode (see SOCKET_I in sock.h)
    def SOCKET_I(self, inode):
        # if too many of these, write a container_of
        backsize = self.profile.get_obj_size("socket")
        addr = inode - backsize

        return obj.Object('socket', offset = addr, vm = self.addr_space)
