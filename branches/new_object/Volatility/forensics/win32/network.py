# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
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
@author:       AAron Walters
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

import struct
import forensics.win32 as win32
import forensics.object2 as object2
from forensics.object import read_obj, get_obj_offset
from forensics.win32.datetime import read_time, windows_to_unix_time
from socket import ntohs, inet_ntoa

module_versions = { \
'MP' : { \
  'TCBTableOff' : [0x497e8], \
  'SizeOff' : [0x3f7c8], \
  'AddrObjTableOffset' : [0x48760], \
  'AddrObjTableSizeOffset' : [0x48764], \
},
'UP' : { \
  'TCBTableOff' : [0x495e8], \
  'SizeOff' : [0x3f5bc], \
  'AddrObjTableOffset' : [0x48560], \
  'AddrObjTableSizeOffset' : [0x48564], \
},
'2180' : { \
  'TCBTableOff' : [0x493e8], \
  'SizeOff' : [0x3f3b0], \
  'AddrObjTableOffset'  : [0x48360], \
  'AddrObjTableSizeOffset' : [0x48364], \
},
'3244' : { \
  'TCBTableOff' : [0x496E8], \
  'SizeOff' : [0x3F6BC], \
  'AddrObjTableOffset'  : [0x48660], \
  'AddrObjTableSizeOffset' : [0x48664], \
},
'3394': {
  'TCBTableOff': [0x49768], \
  'SizeOff': [0x3F73C], \
  'AddrObjTableOffset': [0x486E0], \
  'AddrObjTableSizeOffset': [0x486E4], \
},
'5625' : { \
  'TCBTableOff' : [0x49ae8], \
  'SizeOff' : [0x3fac8], \
  'AddrObjTableOffset'  : [0x48a60], \
  'AddrObjTableSizeOffset' : [0x48a64], \
},
'2111' : { \
  'TCBTableOff' : [0x49A68], \
  'SizeOff' : [0x3FA48], \
  'AddrObjTableOffset'  : [0x489E0], \
  'AddrObjTableSizeOffset' : [0x489E4], \
}
}


def determine_connections(addr_space, profile):
    """Determines all connections for each module"""
    all_modules = win32.modules.lsmod(addr_space, profile)
    connections = []

    for m in all_modules:
        if str(m.ModuleName).lower() == 'tcpip.sys':
            for attempt in module_versions:
                table_size = object2.NewObject(
                    "unsigned long",
                    m.BaseAddress + module_versions[attempt]['SizeOff'][0],
                    addr_space, profile=profile)
                
                table_addr = object2.NewObject(
                    "unsigned long",
                    m.BaseAddress + module_versions[attempt]['TCBTableOff'][0],
                    addr_space, profile=profile)
                
                if int(table_size) > 0:
                    table = object2.Array(
                        offset = table_addr, vm = addr_space,
                        count = table_size, profile = profile, 
                        target = object2.Curry(object2.Pointer, '_TCPT_OBJECT'))

                    for entry in table:
                        conn = entry.dereference()
                        while conn.is_valid():
                            connections.append(conn)
                            conn = conn.Next
            return connections

    return object2.NoneObject("Unable to determine connections")

def determine_sockets(addr_space, profile):
    """Determines all sockets for each module"""
    all_modules = win32.modules.lsmod(addr_space, profile)
    sockets = []

    for m in all_modules:
        if str(m.ModuleName).lower() == 'tcpip.sys':
            for attempt in module_versions:
                table_size = object2.NewObject(
                    "unsigned long",
                    m.BaseAddress + module_versions[attempt]['AddrObjTableSizeOffset'][0],
                    addr_space, profile=profile)
                
                table_addr = object2.NewObject(
                    "unsigned long",
                    m.BaseAddress + module_versions[attempt]['AddrObjTableOffset'][0],
                    addr_space, profile=profile)
                
                if int(table_size) > 0:
                    table = object2.Array(
                        offset = table_addr, vm = addr_space,
                        count = table_size, profile = profile,
                        target = object2.Curry(object2.Pointer, "_ADDRESS_OBJECT"))
                    
                    for entry in table:
                        sock = entry.dereference()
                        while sock.is_valid():
                            sockets.append(sock)
                            sock = sock.Next
            return sockets

    return object2.NoneObject("Unable to determine sockets")

def connection_pid(addr_space, types, connection_vaddr):
    return read_obj(addr_space, types,
                    ['_TCPT_OBJECT', 'Pid'], connection_vaddr)

def connection_lport(addr_space, types, connection_vaddr):
    return ntohs(read_obj(addr_space, types,
                    ['_TCPT_OBJECT', 'LocalPort'], connection_vaddr))

def connection_laddr(addr_space, types, connection_vaddr):
    laddr = read_obj(addr_space, types,
                    ['_TCPT_OBJECT', 'LocalIpAddress'], connection_vaddr)
    return inet_ntoa(struct.pack('=L', laddr)) 

def connection_rport(addr_space, types, connection_vaddr):
    return ntohs(read_obj(addr_space, types,
                    ['_TCPT_OBJECT', 'RemotePort'], connection_vaddr))

def connection_raddr(addr_space, types, connection_vaddr):
    raddr = read_obj(addr_space, types,
                    ['_TCPT_OBJECT', 'RemoteIpAddress'], connection_vaddr)
    return inet_ntoa(struct.pack('=L', raddr))    

def socket_pid(addr_space, types, socket_vaddr):
    return read_obj(addr_space, types,
                    ['_ADDRESS_OBJECT', 'Pid'], socket_vaddr)

def socket_protocol(addr_space, types, socket_vaddr):
    return read_obj(addr_space, types,
                    ['_ADDRESS_OBJECT', 'Protocol'], socket_vaddr)

def socket_local_port(addr_space, types, socket_vaddr):
    return ntohs(read_obj(addr_space, types,
                    ['_ADDRESS_OBJECT', 'LocalPort'], socket_vaddr))

def socket_create_time(addr_space, types, socket_vaddr):
    (create_time_offset, _tmp) = get_obj_offset(types, ['_ADDRESS_OBJECT', 'CreateTime'])    
    create_time     = read_time(addr_space, types, socket_vaddr + create_time_offset)
    if create_time == None:
        return None

    create_time     = windows_to_unix_time(create_time)
    return create_time
