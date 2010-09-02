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

""" This is a concrete implementation of the text renderer """
import volatility.UI as UI

class Table(UI.Table):
    ## Default formatter is just ""
    default_formatter = "{0}"
    max_column_width = 20

    ## We cache a few rows before we print them so we can get a better
    ## idea of the maximum width of each column
    row_cache_size = 20

    def __init__(self, headings, output, format):
        UI.Table.__init__(self, headings = headings, output = output, format = format)
        self.headings_emitted = False
        self.column_count = len(headings)
        self.column_widths = [1] * len(headings)
        self.column_formats = [''] * len(headings)
        self.row_cache = []
        self.row_cache_format = []

    def row(self, *args):
        ## Format each item according to its format string
        row = []
        formats = []
        for i in range(len(args)):
            format = self.format.get(self.headings[i], self.default_formatter)
            #item = "{{0:{0}}}".format(format).format(args[i])
            item = format.format(args[i])
            self.column_widths[i] = max(self.column_widths[i], len(item))

            row.append(item)
            formats.append(format)

        self.row_cache.append(row)
        if len(self.row_cache) > self.row_cache_size:
            self.flush()

    def flush(self):
        if not self.headings_emitted:
            line = ''
            for i in range(len(self.headings)):
                line += "{0:{2}{1:d}} ".format(self.headings[i], self.column_widths[i], '<')
            self.output.write(line.strip() + "\n")

            line = ''
            for i in range(len(self.headings)):
                line += '-' * self.column_widths[i] + " "

            self.output.write(line.strip() + "\n")

            self.headings_emitted = True


        for row in self.row_cache:
            line = ''
            for i in range(len(row)):
                format = self.format.get(self.headings[i], self.default_formatter)
                #line += "{{0:{1:d}{0}}}  ".format(format, self.column_widths[i]).format(row[i])
                #line += "{0:{2}{1:d}} ".format(row[i], self.column_widths[i], format)
                line += "{0:{1:d}} ".format(row[i], self.column_widths[i], format)

            self.output.write(line.strip() + "\n")

        self.row_cache = []

    def __del__(self):
        self.flush()

class text(UI.UI):
    """ Renders output using plain Text """
    def table(self, *args, **kwargs):
        return Table(headings = args, output = self.outfd,
                     format = kwargs.get('format'))

    def rule(self):
        self.outfd.write("*" * 72 + "\n")

    def para(self, data):
        self.outfd.write(data + "\n\n")

    def text(self, data):
        self.outfd.write(data + "\n")
