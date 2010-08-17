# Volatility
# Copyright (C) 2008 Volatile Systems
#
# Additional Authors:
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
# Based heavily upon the getsids plugin by Moyix
# http://kurtz.cs.wesleyan.edu/%7Ebdolangavitt/memory/getsids.py

"""
@author:       AAron Walters and Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com,bdolangavitt@wesleyan.edu
@organization: Volatile Systems
"""


import volatility.conf as conf
import volatility.win32 as win32
import volatility.obj as obj
import volatility.utils as utils
import taskmods
import re

config = conf.ConfObject()

def find_sid_re(sid_string, sid_re_list):
    for reg, name in sid_re_list:
        if reg.search(sid_string):
            return name

well_known_sid_re = [
  (re.compile(r'S-1-5-[0-9-]+-500'), 'Administrator'),
  (re.compile(r'S-1-5-[0-9-]+-501'), 'Guest'),
  (re.compile(r'S-1-5-[0-9-]+-502'), 'KRBTGT'),
  (re.compile(r'S-1-5-[0-9-]+-512'), 'Domain Admins'),
  (re.compile(r'S-1-5-[0-9-]+-513'), 'Domain Users'),
  (re.compile(r'S-1-5-[0-9-]+-514'), 'Domain Guests'),
  (re.compile(r'S-1-5-[0-9-]+-515'), 'Domain Computers'),
  (re.compile(r'S-1-5-[0-9-]+-516'), 'Domain Controllers'),
  (re.compile(r'S-1-5-[0-9-]+-517'), 'Cert Publishers'),
  (re.compile(r'S-1-5-[0-9-]+-520'), 'Group Policy Creator Owners'),
  (re.compile(r'S-1-5-[0-9-]+-533'), 'RAS and IAS Servers'),
  (re.compile(r'S-1-5-5-[0-9]+-[0-9]+'), 'Logon Session'),
]

well_known_sids = {
  'S-1-0': 'Null Authority',
  'S-1-0-0': 'Nobody',
  'S-1-1': 'World Authority',
  'S-1-1-0': 'Everyone',
  'S-1-2-0': 'Users with the ability to log in locally',
  'S-1-2': 'Local Authority',
  'S-1-3': 'Creator Authority',
  'S-1-3-0': 'Creator Owner',
  'S-1-3-1': 'Creator Group',
  'S-1-3-2': 'Creator Owner Server',
  'S-1-3-3': 'Creator Group Server',
  'S-1-4': 'Non-unique Authority',
  'S-1-5': 'NT Authority',
  'S-1-5-1': 'Dialup',
  'S-1-5-2': 'Network',
  'S-1-5-3': 'Batch',
  'S-1-5-4': 'Interactive',
  'S-1-5-6': 'Service',
  'S-1-5-7': 'Anonymous',
  'S-1-5-8': 'Proxy',
  'S-1-5-9': 'Enterprise Domain Controllers',
  'S-1-5-10': 'Principal Self',
  'S-1-5-11': 'Authenticated Users',
  'S-1-5-12': 'Restricted Code',
  'S-1-5-13': 'Terminal Server Users',
  'S-1-5-18': 'Local System',
  'S-1-5-19': 'NT Authority',
  'S-1-5-20': 'NT Authority',
  'S-1-5-32-544': 'Administrators',
  'S-1-5-32-545': 'Users',
  'S-1-5-32-546': 'Guests',
  'S-1-5-32-547': 'Power Users',
  'S-1-5-32-548': 'Account Operators',
  'S-1-5-32-549': 'Server Operators',
  'S-1-5-32-550': 'Print Operators',
  'S-1-5-32-551': 'Backup Operators',
  'S-1-5-32-552': 'Replicators',
  'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
  'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
  'S-1-5-32-556': 'BUILTIN\Network Configuration Operators',
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
  'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
  'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
  'S-1-5-32-559': 'BUILTIN\Performance Log Users',
  'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
  'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
  'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
}

token_types = {
  '_EPROCESS': [ None, {
    'Token' : [ 0xc8, ['_EX_FAST_REF']],
} ],
  '_TOKEN' : [ 0xa8, {
    'UserAndGroupCount' : [ 0x4c, ['unsigned long']],
    'UserAndGroups' : [ 0x68, ['pointer', ['array', lambda x: x.UserAndGroupCount,
                                 ['_SID_AND_ATTRIBUTES']]]],
} ],
  '_SID_AND_ATTRIBUTES' : [ 0x8, {
    'Sid' : [ 0x0, ['pointer', ['_SID']]],
    'Attributes' : [ 0x4, ['unsigned long']],
} ],
  '_SID' : [ 0xc, {
    'Revision' : [ 0x0, ['unsigned char']],
    'SubAuthorityCount' : [ 0x1, ['unsigned char']],
    'IdentifierAuthority' : [ 0x2, ['_SID_IDENTIFIER_AUTHORITY']],
    'SubAuthority' : [ 0x8, ['array', lambda x: x.SubAuthorityCount, ['unsigned long']]],
} ],
  '_SID_IDENTIFIER_AUTHORITY' : [ 0x6, {
    'Value' : [ 0x0, ['array', 6, ['unsigned char']]],
} ],
  '_EX_FAST_REF' : [ 0x4, {
    'Object' : [ 0x0, ['pointer', ['void']]],
    'Value' : [ 0x0, ['unsigned long']],
} ],
}

class getsids(taskmods.dlllist):
    """Print the SIDs owning each process"""

    # Declare meta information associated with this plugin

    meta_info = {}
    meta_info['author'] = 'Brendan Dolan-Gavitt'
    meta_info['copyright'] = 'Copyright (c) 2007,2008 Brendan Dolan-Gavitt'
    meta_info['contact'] = 'bdolangavitt@wesleyan.edu'
    meta_info['license'] = 'GNU General Public License 2.0 or later'
    meta_info['url'] = 'http://moyix.blogspot.com/'
    meta_info['os'] = 'WIN_32_XP_SP2'
    meta_info['version'] = '1.0'

    def calculate(self):
        """Produces a list of processes, or just a single process based on an OFFSET"""
        addr_space = utils.load_as()
        addr_space.profile.add_types(token_types)

        if config.OFFSET != None:
            tasks = [obj.Object("_EPROCESS", config.OFFSET, addr_space)]
        else:
            tasks = self.filter_tasks(win32.tasks.pslist(addr_space))

        return tasks

    def render_text(self, outfd, data):
        """Renders the sids as text"""
        for task in data:
            if not task.Token.is_valid():
                outfd.write("{0} ({1}): Token unreadable\n".format(task.ImageFileName, int(task.UniqueProcessId)))
                continue
            tok = obj.Object('_TOKEN', task.Token.Value & ~0x7, task.vm)

            for sa in tok.UserAndGroups.dereference():
                sid = sa.Sid.dereference()
                for i in sid.IdentifierAuthority.Value:
                    id_auth = i
                sid_string = "S-" + "-".join(str(i) for i in (sid.Revision, id_auth) + tuple(sid.SubAuthority))
                if sid_string in well_known_sids:
                    sid_name = " ({0})".format(well_known_sids[sid_string])
                else:
                    sid_name_re = find_sid_re(sid_string, well_known_sid_re)
                    if sid_name_re:
                        sid_name = " ({0})".format(sid_name_re)
                    else:
                        sid_name = ""

                outfd.write("{0} ({1}): {2}{3}\n".format(task.ImageFileName, task.UniqueProcessId, sid_string, sid_name))
