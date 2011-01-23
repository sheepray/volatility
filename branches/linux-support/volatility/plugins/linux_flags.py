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

# flags used throughout the plugins
# these aren't going to change due to binary breakage if they would

VM_READ = 0x00000001
VM_WRITE = 0x00000002
VM_EXEC = 0x00000004

IPPROTO_IP = 0
IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_IPV6 = 41
IPPROTO_RAW = 255

protocol_strings = {IPPROTO_IP:"IP", IPPROTO_ICMP:"ICMP", IPPROTO_TCP:"TCP", IPPROTO_UDP:"UDP", IPPROTO_IPV6:"IPV6", IPPROTO_RAW:"RAW"}

tcp_states = ("",
              "ESTABLISHED",
              "SYN_SENT",
              "SYN_RECV",
              "FIN_WAIT1",
              "FIN_WAIT2",
              "TIME_WAIT",
              "CLOSE",
              "CLOSE_WAIT",
              "LAST_ACK",
              "LISTEN",
              "CLOSING")

