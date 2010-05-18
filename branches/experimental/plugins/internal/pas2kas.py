import volatility.conf as conf
config = conf.ConfObject()
import volatility.utils as utils
import volatility.commands as commands
import pdb
import bisect

class PAS2KAS(commands.command):
    """ Convert a list of physical AS offsets (given on the command
    line) to a list of potential KVA addresses.
    """
    def render_text(self, outfd, data):
        outfd.write("{0:10s} {1:10s}\n".format("Phys AS", "KAS"))
        for offset, result in data:
            outfd.write("0x{0:08x} 0x{1:08x}\n".format(offset, result))

    def coalesce_ranges(self, addr_space):
        """ Coalesce the page range given into large groups """
        last_va = 0
        last_pa = 0
        last_len = 0

        for va, length in addr_space.get_available_pages():
            pa = addr_space.vtop(va)
            if pa == None:
                continue

            ## This page is right after the last page in the range
            if (va - last_va) == (pa - last_pa):
                last_len += length
            else:
                if last_len>0:
                    yield (last_va, last_pa, last_len)

                last_va, last_pa, last_len = va, pa, length

        yield (last_va, last_pa, last_len)

    def calculate(self):
        addr_space = utils.load_as()

        ## Get the coalesced map:
        ranges = [ (va, pa, length) for va, pa, length in self.coalesce_ranges(addr_space) ]

        ## Now for each Physical address, find all Virtual Addresses
        ## for it. We optimise by sorting on pa and use binary
        ## search via the bisect module to get O(log n) here.
        config.parse_options()
        for pa in config.args[1:]:
            needle = conf.parse_int(pa)
            for va, pa, length in ranges:
                if needle >= pa and needle - pa < length:
                    pdb.set_trace()
                    yield (needle, va + (needle - pa))
