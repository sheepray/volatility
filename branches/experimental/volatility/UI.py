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

""" This plugin provides abstract output for volatility plugins """
import sys
import volatility.conf as conf

config = conf.ConfObject()

class Table:
    """ A table formats the output in columns.

    headings - a list of heading names
    formatters - a dict with keys = headings and values being the formatting characters for each object.
    outfd - a writable object for outputting the data to.
    """
    def __init__(self, headings, output, format = None):
        self.headings = headings
        self.output = output
        self.format = format or {}

    def row(self, *args):
        """ This function adds a new row to this table """

class UI:
    """ An abstract class for outputting volatility data.
    """
    def __init__(self, outfd = None):
        self.outfd = outfd
        if not self.outfd:
            self.outfd = sys.stdout

    def table(self, headings, output, format=None):
        return Table(headings, self.outfd, format)

    def progress(self, percentage = None):
        """ This method is called to indicate to the user progress is made.

        If percentage is provided it represents the percentage left
        until the task is done.
        """
