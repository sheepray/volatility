#!/usr/bin/env python
#  -*- mode: python; -*-
#
# canon_vtypes.py
# Copyright (C) 2010 Brendan Dolan-Gavitt
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
@author:       Brendan Dolan-Gavitt
@license:      GNU General Public License 2.0 or later
@contact:      brendandg@gatech.edu
@organization: Georgia Institute of Technology
"""

from optparse import OptionParser
import hashlib
import dwarfparse
import sys

def print_vtypes(vtypes,name="the_types",msizes=True):
    print "%s = {" % name
    for t in sorted(vtypes):
        print "  '%s': [ %#x, {" % (t, vtypes[t][0])
        for m in sorted(vtypes[t][1],key=lambda m: vtypes[t][1][m][0]):
            if msizes:
                print "    '%s': [%#x, %s]," % (m, vtypes[t][1][m][0], vtypes[t][1][m][1])
            else:
                print "    '%s': [-, %s]," % (m, vtypes[t][1][m][1])
        print "}],"
    print "}"

def tuplify(types,t):
    if isinstance(t,list) or isinstance(t,tuple):
        return tuple(sorted([tuplify(types,x) for x in t]))
    elif isinstance(t,dict):
        return tuplify(types, t.items())
    elif isinstance(t,str) and 'unnamed' in t:
        return tuplify(types, types[t])
    else:
        return t

usage = "usage: %prog [options] <vtypes> <dictname>"
parser = OptionParser(usage=usage)
parser.add_option("-n", "--no-offsets",
                  action="store_false", dest="offsets", default=True,
                  help="don't print field offsets in output")
(opts, args) = parser.parse_args()

if len(args) != 2:
    parser.error("Must provide both vtypes file and the name of the dictionary in the vtypes file.")

locs, globs = {},{}
execfile(args[0],globs,locs)
vtypes = locs[args[1]]

unnamed = [t for t in vtypes if t.startswith('__unnamed')]

newnames = {}

for t in unnamed:
    newname = "unnamed_" + hashlib.md5(str(tuplify(vtypes,vtypes[t]))).hexdigest()
    newnames[t] = newname

for t in vtypes:
    for m in vtypes[t][1]:
        memb = vtypes[t][1][m]
        d = dwarfparse.get_deepest(memb)
        if d in newnames:
            vtypes[t][1][m] = dwarfparse.deep_replace(memb, d, newnames[d])

for n in newnames:
    vtypes[newnames[n]] = vtypes[n]
    del vtypes[n]

print_vtypes(vtypes, args[1], msizes=opts.offsets)
