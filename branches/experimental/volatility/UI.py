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
