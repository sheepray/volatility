#!/usr/bin/env python2.6
#  -*- mode: python; -*-
#
# dwarfparse.py
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


from pprint import pprint
import fileinput
import sys,os
import re

# Notes:
# 1. IDs are only valid within a compilation unit, so we resolve IDs to
#    specific types before moving on to the next compilation unit.
# 2. Variables are also useful to have, so we include them at the end.
#    As a bonus they include type info!
# 3. As a consequence of (1), we end up with duplicate anonymous unions/enums,
#    because they have different IDs in different compilation units. We try to
#    weed these out at the end right now.

# Nasty, but appears to parse the lines we need
dwarf = re.compile(r'(<(?P<level>\d+)><(?P<id>[0-9+]+)><(?P<kind>\w+)> ?|((?P<keyname>\w+)<(?P<val>.*?)>( |$)))')

def parse_system_map(map_file):

    smap = {}

    try:
        os.stat(map_file)
    except:
        print "Cannot open supplied system map file! %s" % sys.exc_info()[1]
        sys.exit(1)

    # get the system map
    for line in open(map_file,"r").readlines():

        line = line.strip("\n")
        (address,type,symbol) = line.split(" ")
        smap[symbol] = int(address,16)

    return smap


sz2tp = {8: 'long long', 4: 'long', 2: 'short', 1: 'char'}
tp2vol = {
    '_Bool': 'unsigned char',
    'char': 'char',
    'float': 'float',
    'double': 'double',
    'long double': 'double',
    'int': 'int',
    'long int': 'long',
    'long long int': 'long long',
    'long long unsigned int': 'unsigned long long',
    'long unsigned int': 'unsigned long',
    'short int': 'short',
    'short unsigned int': 'unsigned short',
    'signed char': 'signed char',
    'unsigned char': 'unsigned char',
    'unsigned int': 'unsigned int',
}

def deep_replace(t, search, repl):
    if t == search: return repl
    elif isinstance(t, list):
        return [deep_replace(x,search,repl) for x in t]
    else: return t

def get_deepest(t):
    if isinstance(t, list):
        if len(t) == 1: return t[0]
        else:
            for part in t:
                res = get_deepest(part)
                if res: return res
            return None
    return None

def resolve(memb, id_to_name):
    if isinstance(memb, str) and memb.startswith('<'):
        resolved = id_to_name[memb[1:-1]]
        return resolve(resolved, id_to_name)
    elif isinstance(memb, list):
        return [resolve(r,id_to_name) for r in memb]
    else:
        return memb

def resolve_refs(vtypes, id_to_name):
    for v in vtypes:
        for m in vtypes[v][1]:
            vtypes[v][1][m] = resolve(vtypes[v][1][m], id_to_name)
    return vtypes

def base_type_name(parsed):
    if 'DW_AT_name' in parsed['data']:
        return tp2vol[parsed['data']['DW_AT_name']]
    else:
        sz = int(parsed['data']['DW_AT_byte_size'])
        if parsed['data']['DW_AT_encoding'] == 'DW_ATE_unsigned':
            return 'unsigned ' + sz2tp[sz]
        else:
            return sz2tp[sz]

if __name__ == "__main__":
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option('-l', '--locals', action="store_true", dest="locals", default=False, help="print locals")
    parser.add_option('-s', '--system_map', action="store", dest="map_file", default="", help="system map file path")
    (options, args) = parser.parse_args()

    current_level = -1
    name_stack = []
    id_to_name = {}
    all_vtypes = {}
    vtypes = {}
    enums = {}
    all_vars = {}
    vars = {}
    all_local_vars = []
    local_vars = []
    anons = 0

    for line in fileinput.input(args):
        if not line.startswith('<'): continue

        # Parse
        line = line.strip()
        parsed = {}
        parsed['data'] = {}
        it = dwarf.finditer(line)
        try:
            header = it.next().groupdict()
        except StopIteration:
            continue
        parsed.update(dict( (k,v) for k,v in header.items() if v ))
        for m in it:
            d = m.groupdict()
            parsed['data'][d['keyname']] = d['val']
        
        new_level = int(parsed['level'])
        if new_level > current_level:
            current_level = new_level
            name_stack.append(())
        elif new_level < current_level:
            for i in range(current_level - new_level): name_stack.pop()
            current_level = new_level
        new_kind = parsed['kind']
        new_name = parsed['id'] # Just a default, we'll override it later
        name_stack[-1] = (new_kind, new_name)
        parent_kind, parent_name = name_stack[-2] if len(name_stack) > 1 else (None,None)

        # Track all variables and parameters
        if options.locals and parsed['kind'] in ('DW_TAG_formal_parameter','DW_TAG_variable'):
            if ('DW_AT_name' in parsed['data'] and
                'DW_AT_decl_line' in parsed['data'] and
                'DW_AT_type' in parsed['data']):
                lineno = int(parsed['data']['DW_AT_decl_line'])
                name = parsed['data']['DW_AT_name']
                tp = parsed['data']['DW_AT_type']
                decl_file = parsed['data']['DW_AT_decl_file'].split()[1]
                local_vars.append( (name, lineno, decl_file, tp) )
    
        # Work
        if parsed['kind'] == 'DW_TAG_compile_unit':
            #print "Beginning work on compilation unit: %s" % parsed['data']['DW_AT_name']
            if vtypes:
                vtypes = resolve_refs(vtypes, id_to_name)
                all_vtypes.update(vtypes)
                #print "Found %d structures, total now %d" % (len(vtypes), len(all_vtypes))
                vtypes = {}
            if vars:
                vars = dict(((k,resolve(v,id_to_name)) for k,v in vars.items()))
                all_vars.update(vars)
                vars = {}
            if local_vars:
                local_vars = [ (name, lineno, decl_file, resolve(tp,id_to_name)) for
                               (name, lineno, decl_file, tp) in local_vars ]
                all_local_vars += local_vars
            id_to_name = {}
        elif parsed['kind'] == 'DW_TAG_structure_type':
            try:
                name = parsed['data']['DW_AT_name']
            except KeyError:
                name = "__unnamed_%d" % anons
                anons += 1
            name_stack[-1] = (name_stack[-1][0], name)
            id_to_name[parsed['id']] = [name]

            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'DW_AT_declaration' in parsed['data']: continue
            
            vtypes[name] = [ int(parsed['data']['DW_AT_byte_size']), {} ]
        elif parsed['kind'] == 'DW_TAG_union_type':
            try:
                name = parsed['data']['DW_AT_name']
            except KeyError:
                name = "__unnamed_%d" % anons
                anons += 1
            name_stack[-1] = (name_stack[-1][0], name)
            id_to_name[parsed['id']] = [name]
            vtypes[name] = [ int(parsed['data']['DW_AT_byte_size']), {} ]
        elif parsed['kind'] == 'DW_TAG_array_type':
            name_stack[-1] = (name_stack[-1][0], parsed['id'])
            id_to_name[parsed['id']] = parsed['data']['DW_AT_type']
        elif parsed['kind'] == 'DW_TAG_enumeration_type':
            try:
                name = parsed['data']['DW_AT_name']
            except KeyError:
                name = "__unnamed_%d" % anons
                anons += 1
            name_stack[-1] = (name_stack[-1][0], name)
            id_to_name[parsed['id']] = [name]

            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'DW_AT_declaration' in parsed['data']: continue

            sz = int(parsed['data']['DW_AT_byte_size'])
            enums[name] = [sz,{}]
        elif parsed['kind'] == 'DW_TAG_pointer_type':
            id_to_name[parsed['id']] = ['pointer', parsed['data'].get('DW_AT_type',['void'])]
        elif parsed['kind'] == 'DW_TAG_base_type':
            id_to_name[parsed['id']] = [base_type_name(parsed)]
        elif parsed['kind'] == 'DW_TAG_volatile_type':
            id_to_name[parsed['id']] = parsed['data'].get('DW_AT_type','void')
        elif parsed['kind'] == 'DW_TAG_const_type':
            id_to_name[parsed['id']] = parsed['data'].get('DW_AT_type','void')
        elif parsed['kind'] == 'DW_TAG_typedef':
            id_to_name[parsed['id']] = parsed['data']['DW_AT_type']
        elif parsed['kind'] == 'DW_TAG_subroutine_type':
            id_to_name[parsed['id']] = ['void']         # Don't need these
        elif parsed['kind'] == 'DW_TAG_variable' and parsed['level'] == '1':
            if 'DW_AT_location' in parsed['data']:
                split = parsed['data']['DW_AT_location'].split()
                if len(split) > 1:
                    loc = int(split[1],0)
                    vars[parsed['data']['DW_AT_name']] = [loc, parsed['data']['DW_AT_type']]
        elif parsed['kind'] == 'DW_TAG_subprogram':
            # IDEK
            pass
        elif parsed['kind'] == 'DW_TAG_member' and parent_kind == 'DW_TAG_structure_type':
            try:
                name = parsed['data']['DW_AT_name']
            except KeyError:    # Anonymous struct member, for example
                name = "__unnamed_%d" % anons
                anons += 1
            off = int(parsed['data']['DW_AT_data_member_location'].split()[1])
            if 'DW_AT_bit_size' in parsed['data'] and 'DW_AT_bit_offset' in parsed['data']:
                full_size = int(parsed['data']['DW_AT_byte_size'])*8
                stbit = int(parsed['data']['DW_AT_bit_offset'])
                edbit = stbit + int(parsed['data']['DW_AT_bit_size'])
                stbit = full_size - stbit
                edbit = full_size - edbit
                stbit,edbit = edbit,stbit
                assert stbit < edbit
                memb_tp = ['BitField', dict(start_bit = stbit, end_bit = edbit)]
            else:
                memb_tp = parsed['data']['DW_AT_type']
            vtypes[parent_name][1][name] = [off, memb_tp]
        elif parsed['kind'] == 'DW_TAG_member' and parent_kind == 'DW_TAG_union_type':
            try:
                name = parsed['data']['DW_AT_name']
            except KeyError:    # Anonymous union member, for example
                name = "__unnamed_%d" % anons
                anons += 1
            vtypes[parent_name][1][name] = [0, parsed['data']['DW_AT_type']]
        elif parsed['kind'] == 'DW_TAG_enumerator' and parent_kind == 'DW_TAG_enumeration_type':
            name = parsed['data']['DW_AT_name']
            try:
                val = int(parsed['data']['DW_AT_const_value'])
            except ValueError:
                sz = int(parsed['data']['DW_AT_const_value'].split('(')[0])
            enums[parent_name][1][name] = val
        elif parsed['kind'] == 'DW_TAG_subrange_type' and parent_kind == 'DW_TAG_array_type':
            if 'DW_AT_upper_bound' in parsed['data']:
                try:
                    sz = int(parsed['data']['DW_AT_upper_bound'])
                except ValueError:
                    sz = int(parsed['data']['DW_AT_upper_bound'].split('(')[0])
                sz += 1
            else:
                sz = 0
            tp = id_to_name[parent_name]
            id_to_name[parent_name] = ['array', sz, tp]
        else:
            pass
            #print "Skipping unsupported tag %s" % parsed['kind']
    
    if vtypes:
        vtypes = resolve_refs(vtypes, id_to_name)
        all_vtypes.update(vtypes)
    if vars:
        vars = dict(((k,resolve(v,id_to_name)) for k,v in vars.items()))
        all_vars.update(vars)
    if local_vars:
        local_vars = [ (name, lineno, decl_file, resolve(tp,id_to_name)) for
                       (name, lineno, decl_file, tp) in local_vars ]
        all_local_vars += local_vars

    orig = len(all_vtypes)
    # Get rid of unneeded unknowns (shades of Rumsfeld here)
    # Needs to be done in fixed point fashion
    changed = True
    while changed:
        changed = False
        s = set()
        for m in all_vtypes:
            for t in all_vtypes[m][1].values():
                s.add(get_deepest(t))
        for m in all_vars:
            s.add(get_deepest(all_vars[m][1]))
        for v in list(all_vtypes):
            if v.startswith('__unnamed_') and v not in s:
                del all_vtypes[v]
                changed = True

    # Merge the enums into the types directly:
    for t in all_vtypes:
        for m in list(all_vtypes[t][1]):
            memb = all_vtypes[t][1][m]
            d = get_deepest(memb)
            if d in enums:
                sz = enums[d][0]
                vals = dict((v,k) for k,v in enums[d][1].items())
                all_vtypes[t][1][m] = deep_replace(memb, [d],
                    ['Enumeration', dict(target = sz2tp[sz], choices = vals)]
                )

    # Print stuff out
    if options.locals:
        #print "linux_locals = ["
        print "\n".join("  " + str(l) + "," for l in local_vars)
        #print "]"
    else:
        print "linux_types = {"

        if options.map_file:
            system_map = parse_system_map(options.map_file)
            dtb = system_map["swapper_pg_dir"] - 0xc0000000
            print "'VOLATILITY_MAGIC' : [None, {'DTB' : [ 0x00, ['VolatilityMagic', dict(value = %d)]]," % dtb
            print "'system_map' : [  0x00, ['VolatilityMagic',dict(value = " + str(system_map) + " )]], }], "

        for t in all_vtypes:
            print "  '%s': [ %#x, {" % (t, all_vtypes[t][0])
            for m in sorted(all_vtypes[t][1],key=lambda m: all_vtypes[t][1][m][0]):
                print "    '%s': [%#x, %s]," % (m, all_vtypes[t][1][m][0], all_vtypes[t][1][m][1])
            print "}],"
        print "}"
        print
        print "linux_gvars = {"
        for v in sorted(all_vars, key=lambda v: all_vars[v][0]):
            print "  '%s': [%#010x, %s]," % (v, all_vars[v][0], all_vars[v][1])
        print "}"
