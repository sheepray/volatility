'''
Created on 31 Dec 2010

@author: mike
'''

tcpip_vtypes = {\
  '_ADDRESS_OBJECT' : [ 0x68, { \
    'Next' : [ 0x0, ['pointer', ['_ADDRESS_OBJECT']]], \
    'LocalIpAddress' : [ 0x0c, ['unsigned long']], \
    'LocalPort' : [ 0x30, ['unsigned short']], \
    'Protocol'  : [ 0x32, ['unsigned short']], \
    'Pid' : [ 0x148, ['unsigned long']], \
    'CreateTime' : [ 0x158, ['_LARGE_INTEGER']], \
} ], \
  '_TCPT_OBJECT' : [ 0x20, { \
  'Next' : [ 0x0, ['pointer', ['_TCPT_OBJECT']]], \
  'RemoteIpAddress' : [ 0xc, ['unsigned long']], \
  'LocalIpAddress' : [ 0x10, ['unsigned long']], \
  'RemotePort' : [ 0x14, ['unsigned short']], \
  'LocalPort' : [ 0x16, ['unsigned short']], \
  'Pid' : [ 0x18, ['unsigned long']], \
} ], \
  '_OBJECT_HEADER_NAME_INFORMATION' : [ 0xc, {
  'Directory' : [ 0x0, ['pointer', ['_OBJECT_DIRECTORY']]],
  'Name' : [ 0x04, ['_UNICODE_STRING']],
} ], \
}
