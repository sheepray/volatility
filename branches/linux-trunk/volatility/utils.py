# Volatility
#
# Authors:
# Michael Cohen <scudette@users.sourceforge.net>
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

import re

import volatility.exceptions as exceptions
import volatility.registry as registry
import volatility.addrspace as addrspace
import volatility.debug as debug
import socket
import itertools

#pylint: disable-msg=C0111

def load_as(config, astype = 'virtual', **kwargs):
    """Loads an address space by stacking valid ASes on top of each other (priority order first)"""

    base_as = None
    error = exceptions.AddrSpaceError()

    # Start off requiring another round    
    found = True
    ## A full iteration through all the classes without anyone
    ## selecting us means we are done:
    while found:
        debug.debug("Voting round")
        found = False
        for cls in sorted(registry.get_plugin_classes(addrspace.BaseAddressSpace).values(),
                          key = lambda x: x.order if hasattr(x, 'order') else 10):
            debug.debug("Trying {0} ".format(cls))
            try:
                base_as = cls(base_as, config, astype = astype, **kwargs)
                debug.debug("Succeeded instantiating {0}".format(base_as))
                found = True
                break
            except addrspace.ASAssertionError, e:
                debug.debug("Failed instantiating {0}: {1}".format(cls.__name__, e), 2)
                error.append_reason(cls.__name__, e)
                continue
            except Exception, e:
                debug.debug("Failed instantiating (exception): {0}".format(e))
                error.append_reason(cls.__name__ + " - EXCEPTION", e)
                continue

    if not isinstance(base_as, addrspace.AbstractVirtualAddressSpace) and (astype == 'virtual'):
        base_as = None

    if base_as is None:
        raise error

    return base_as

def Hexdump(data, width = 16):
    """ Hexdump function shared by various plugins """
    for offset in xrange(0, len(data), width):
        row_data = data[offset:offset + width]
        translated_data = [x if ord(x) < 127 and ord(x) > 32 else "." for x in row_data]
        hexdata = " ".join(["{0:02x}".format(ord(x)) for x in row_data])

        yield offset, hexdata, translated_data

# Compensate for Windows python not supporting socket.inet_ntop and some
# Linux systems (i.e. OpenSuSE 11.2 w/ Python 2.6) not supporting IPv6. 

def inet_ntop(address_family, packed_ip):

    def inet_ntop4(packed_ip):
        if not isinstance(packed_ip, str):
            raise TypeError("must be string, not {0}".format(type(packed_ip)))
        if len(packed_ip) != 4:
            raise ValueError("invalid length of packed IP address string")
        return "{0}.{1}.{2}.{3}".format(*[ord(x) for x in packed_ip])

    def inet_ntop6(packed_ip):
        if not isinstance(packed_ip, str):
            raise TypeError("must be string, not {0}".format(type(packed_ip)))
        if len(packed_ip) != 16:
            raise ValueError("invalid length of packed IP address string")

        words = []
        for i in range(0, 16, 2):
            words.append((ord(packed_ip[i]) << 8) | ord(packed_ip[i + 1]))

        # Replace a run of 0x00s with None
        numlen = [(k, len(list(g))) for k, g in itertools.groupby(words)]
        max_zero_run = sorted(sorted(numlen, key = lambda x: x[1], reverse = True), key = lambda x: x[0])[0]
        words = []
        for k, l in numlen:
            if (k == 0) and (l == max_zero_run[1]) and not (None in words):
                words.append(None)
            else:
                for i in range(l):
                    words.append(k)

        # Handle encapsulated IPv4 addresses
        encapsulated = ""
        if (words[0] is None) and (len(words) == 3 or (len(words) == 4 and words[1] == 0xffff)):
            words = words[:-2]
            encapsulated = inet_ntop4(packed_ip[-4:])
        # If we start or end with None, then add an additional :
        if words[0] is None:
            words = [None] + words
        if words[-1] is None:
            words += [None]
        # Join up everything we've got using :s
        return ":".join(["{0:x}".format(w) if w is not None else "" for w in words]) + encapsulated

    if address_family == socket.AF_INET:
        return inet_ntop4(packed_ip)
    elif address_family == socket.AF_INET6:
        return inet_ntop6(packed_ip)
    raise socket.error("[Errno 97] Address family not supported by protocol")

class DWARFParser(object):
    """A parser for DWARF files."""

    # Nasty, but appears to parse the lines we need
    dwarf_header_regex = re.compile(
        r'<(?P<level>\d+)><(?P<statement_id>[0-9+]+)><(?P<kind>\w+)>')
    dwarf_key_val_regex = re.compile(
        '\s*(?P<keyname>\w+)<(?P<val>[^>]*)>')

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


    def __init__(self, data = None):
        self.current_level = -1
        self.name_stack = []
        self.id_to_name = {}
        self.all_vtypes = {}
        self.vtypes = {}
        self.enums = {}
        self.all_vars = {}
        self.vars = {}
        self.all_local_vars = []
        self.local_vars = []
        self.anons = 0

        if data:
            for line in data.splitlines():
                self.feed_line(line)

    def resolve(self, memb):
        """Lookup anonymouse member and replace it with a well known one."""
        # Reference to another type
        if isinstance(memb, str) and memb.startswith('<'):
            resolved = self.id_to_name[memb[1:]]

            return self.resolve(resolved)

        elif isinstance(memb, list):
            return [self.resolve(r) for r in memb]
        else:
            # Literal
            return memb

    def resolve_refs(self):
        """Replace references with types."""
        for v in self.vtypes:
            for m in self.vtypes[v][1]:
                self.vtypes[v][1][m] = self.resolve(self.vtypes[v][1][m])

        return self.vtypes

    def deep_replace(self, t, search, repl):
        """Recursively replace anonymous references."""
        if t == search:
            return repl

        elif isinstance(t, list):
            return [self.deep_replace(x, search, repl) for x in t]
        else: return t

    def get_deepest(self, t):
        if isinstance(t, list):
            if len(t) == 1:
                return t[0]
            else:
                for part in t:
                    res = self.get_deepest(part)
                    if res:
                        return res

                return None

        return None

    def base_type_name(self, data):
        """Replace references to base types."""
        if 'DW_AT_name' in data:
            return self.tp2vol[data['DW_AT_name']]
        else:
            sz = int(data['DW_AT_byte_size'])
            if data['DW_AT_encoding'] == 'DW_ATE_unsigned':
                return 'unsigned ' + self.sz2tp[sz]
            else:
                return self.sz2tp[sz]

    def feed_line(self, line):
        """Accepts another line from the input.

        A DWARF line looks like:
        <2><1442><DW_TAG_member> DW_AT_name<fs>  ...

        The header is level, statement_id, and kind followed by key value pairs.
        """
        # Does the header match?
        m = self.dwarf_header_regex.match(line)
        if m:
            parsed = m.groupdict()
            parsed['data'] = {}
            # Now parse the key value pairs
            while m:
                i = m.end()
                m = self.dwarf_key_val_regex.search(line, i)
                if m:
                    d = m.groupdict()
                    parsed['data'][d['keyname']] = d['val']

            if parsed['kind'] in ('DW_TAG_formal_parameter', 'DW_TAG_variable'):
                self.process_variable(parsed['data'])
            else:
                self.process_statement(**parsed) #pylint: disable-msg=W0142

    def process_statement(self, kind, level, data, statement_id):
        """Process a single parsed statement."""
        new_level = int(level)
        if new_level > self.current_level:
            self.current_level = new_level
            self.name_stack.append([])
        elif new_level < self.current_level:
            self.name_stack = self.name_stack[:new_level + 1]
            self.current_level = new_level

        self.name_stack[-1] = [kind, statement_id]

        try:
            parent_kind, parent_name = self.name_stack[-2]
        except IndexError:
            parent_kind, parent_name = (None, None)

        if kind == 'DW_TAG_compile_unit':
            self.finalize()
            self.vtypes = {}
            self.vars = {}
            self.all_local_vars += self.local_vars
            self.local_vars = []
            self.id_to_name = {}

        elif kind == 'DW_TAG_structure_type':
            name = data.get('DW_AT_name', "__unnamed_%s" % statement_id)
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]

            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'DW_AT_declaration' not in data:
                self.vtypes[name] = [ int(data['DW_AT_byte_size']), {} ]

        elif kind == 'DW_TAG_union_type':
            name = data.get('DW_AT_name', "__unnamed_%s" % statement_id)
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]
            self.vtypes[name] = [ int(data['DW_AT_byte_size']), {} ]

        elif kind == 'DW_TAG_array_type':
            self.name_stack[-1][1] = statement_id
            self.id_to_name[statement_id] = data['DW_AT_type']

        elif kind == 'DW_TAG_enumeration_type':
            name = data.get('DW_AT_name', "__unnamed_%s" % statement_id)
            self.name_stack[-1][1] = name
            self.id_to_name[statement_id] = [name]

            # If it's just a forward declaration, we want the name around,
            # but there won't be a size
            if 'DW_AT_declaration' not in data:
                sz = int(data['DW_AT_byte_size'])
                self.enums[name] = [sz, {}]

        elif kind == 'DW_TAG_pointer_type':
            self.id_to_name[statement_id] = ['pointer', data.get('DW_AT_type', ['void'])]

        elif kind == 'DW_TAG_base_type':
            self.id_to_name[statement_id] = [self.base_type_name(data)]

        elif kind == 'DW_TAG_volatile_type':
            self.id_to_name[statement_id] = data.get('DW_AT_type', ['void'])

        elif kind == 'DW_TAG_const_type':
            self.id_to_name[statement_id] = data.get('DW_AT_type', ['void'])

        elif kind == 'DW_TAG_typedef':
            self.id_to_name[statement_id] = data['DW_AT_type']

        elif kind == 'DW_TAG_subroutine_type':
            self.id_to_name[statement_id] = ['void']         # Don't need these

        elif kind == 'DW_TAG_variable' and level == '1':
            if 'DW_AT_location' in data:
                split = data['DW_AT_location'].split()
                if len(split) > 1:
                    loc = int(split[1], 0)
                    self.vars[data['DW_AT_name']] = [loc, data['DW_AT_type']]

        elif kind == 'DW_TAG_subprogram':
            # IDEK
            pass

        elif kind == 'DW_TAG_member' and parent_kind == 'DW_TAG_structure_type':
            name = data.get('DW_AT_name', "__unnamed_%s" % statement_id)
            off = int(data['DW_AT_data_member_location'].split()[1])

            if 'DW_AT_bit_size' in data and 'DW_AT_bit_offset' in data:
                full_size = int(data['DW_AT_byte_size']) * 8
                stbit = int(data['DW_AT_bit_offset'])
                edbit = stbit + int(data['DW_AT_bit_size'])
                stbit = full_size - stbit
                edbit = full_size - edbit
                stbit, edbit = edbit, stbit
                assert stbit < edbit
                memb_tp = ['BitField', dict(start_bit = stbit, end_bit = edbit)]
            else:
                memb_tp = data['DW_AT_type']

            self.vtypes[parent_name][1][name] = [off, memb_tp]

        elif kind == 'DW_TAG_member' and parent_kind == 'DW_TAG_union_type':
            name = data.get('DW_AT_name', "__unnamed_%s" % statement_id)
            self.vtypes[parent_name][1][name] = [0, data['DW_AT_type']]

        elif kind == 'DW_TAG_enumerator' and parent_kind == 'DW_TAG_enumeration_type':
            name = data['DW_AT_name']

            try:
                val = int(data['DW_AT_const_value'])
            except ValueError:
                val = int(data['DW_AT_const_value'].split('(')[0])

            self.enums[parent_name][1][name] = val

        elif kind == 'DW_TAG_subrange_type' and parent_kind == 'DW_TAG_array_type':
            if 'DW_AT_upper_bound' in data:
                try:
                    sz = int(data['DW_AT_upper_bound'])
                except ValueError:
                    try:
                        sz = int(data['DW_AT_upper_bound'].split('(')[0])
                    except ValueError:
                        # Give up
                        sz = 0
                sz += 1
            else:
                sz = 0

            tp = self.id_to_name[parent_name]
            self.id_to_name[parent_name] = ['array', sz, tp]
        else:
            pass
            #print "Skipping unsupported tag %s" % parsed['kind']


    def process_variable(self, data):
        """Process a local variable."""
        if ('DW_AT_name' in data and 'DW_AT_decl_line' in data and
            'DW_AT_type' in data):
            self.local_vars.append(
                (data['DW_AT_name'], int(data['DW_AT_decl_line']),
                 data['DW_AT_decl_file'].split()[1], data['DW_AT_type']))

    def finalize(self):
        """Finalize the output."""
        if self.vtypes:
            self.vtypes = self.resolve_refs()
            self.all_vtypes.update(self.vtypes)
        if self.vars:
            self.vars = dict(((k, self.resolve(v)) for k, v in self.vars.items()))
            self.all_vars.update(self.vars)
        if self.local_vars:
            self.local_vars = [ (name, lineno, decl_file, self.resolve(tp)) for
                                (name, lineno, decl_file, tp) in self.local_vars ]
            self.all_local_vars += self.local_vars

        # Get rid of unneeded unknowns (shades of Rumsfeld here)
        # Needs to be done in fixed point fashion
        changed = True
        while changed:
            changed = False
            s = set()
            for m in self.all_vtypes:
                for t in self.all_vtypes[m][1].values():
                    s.add(self.get_deepest(t))
            for m in self.all_vars:
                s.add(self.get_deepest(self.all_vars[m][1]))
            for v in list(self.all_vtypes):
                if v.startswith('__unnamed_') and v not in s:
                    del self.all_vtypes[v]
                    changed = True

        # Merge the enums into the types directly:
        for t in self.all_vtypes:
            for m in list(self.all_vtypes[t][1]):
                memb = self.all_vtypes[t][1][m]
                d = self.get_deepest(memb)
                if d in self.enums:
                    sz = self.enums[d][0]
                    vals = dict((v, k) for k, v in self.enums[d][1].items())
                    self.all_vtypes[t][1][m] = self.deep_replace(
                        memb, [d],
                        ['Enumeration', dict(target = self.sz2tp[sz], choices = vals)]
                    )

        return self.all_vtypes

    def print_output(self):
        self.finalize()
        print "linux_types = {"

        for t in self.all_vtypes:
            print "  '%s': [ %#x, {" % (t, self.all_vtypes[t][0])
            for m in sorted(self.all_vtypes[t][1], key = lambda m: self.all_vtypes[t][1][m][0]):
                print "    '%s': [%#x, %s]," % (m, self.all_vtypes[t][1][m][0], self.all_vtypes[t][1][m][1])
            print "}],"
        print "}"
        print
        print "linux_gvars = {"
        for v in sorted(self.all_vars, key = lambda v: self.all_vars[v][0]):
            print "  '%s': [%#010x, %s]," % (v, self.all_vars[v][0], self.all_vars[v][1])
        print "}"

