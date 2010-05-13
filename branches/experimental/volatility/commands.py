# Volatility
# Copyright (C) 2008 Volatile Systems
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


import sys, textwrap
import volatility.conf as conf
import volatility.registry as registry

config = conf.ConfObject()

config.add_option("OUTPUT", default='text',
                  help="Output in this format (format support is module specific)")

config.add_option("OUTPUT-FILE", default=None,
                  help="write output in this file")

config.add_option("VERBOSE", default=0, action='count',
                  short_option='v', help='Verbose information')

class command(object):
    """ Base class for each plugin command """
    op = ""
    opts = ""
    args = ""
    cmdname = ""
    # meta_info will be removed
    meta_info = {}

    def __init__(self, args=None):
        """ Constructor uses args as an initializer. It creates an instance
        of OptionParser, populates the options, and finally parses the 
        command line. Options are stored in the self.opts attribute.
        """
    @classmethod
    def help(cls):
        """ This function returns a string that will be displayed when a
        user lists available plugins.
        """
        try:
            return textwrap.dedent(cls.__doc__)
        except AttributeError:
            return ""

    def calculate(self):
        """ This function is responsible for performing all calculations

        We should not have any output functions (e.g. print) in this
        function at all.

        If this function is expected to take a long time to return
        some data, the function should return a generator.
        """

    def render(self, data, ui):
        """ This function is called to render the output using the
        generic UI methods
        """
        raise RuntimeError("Generic rendering is not implemented for this command")

    def render_xml(self, outfd, data):
        """ Render using the generic rendering method and the text renderer """
        ui = registry.UI_RENDERERS["xml"](outfd)
        return self.render(data, ui)

    def execute(self):
        """ Executes the plugin command."""
        ## Executing plugins is done in two stages - first we calculate
        data = self.calculate()

        ## Then we render the result in some way based on the
        ## requested output mode:
        function_name = "render_{0}".format(config.OUTPUT)
        if config.OUTPUT_FILE:
            outfd = open(config.OUTPUT_FILE,'w')
            # TODO: We should probably check that this won't blat over an existing file 
        else:
            outfd = sys.stdout

        try:
            func = getattr(self, function_name)
        except AttributeError:
            ## is there a generic renderer for this?
            try:
                renderer = registry.UI_RENDERERS[config.OUTPUT]
                func = getattr(self, render)
            except (KeyError, AttributeError):
                ## Try to find out what formats are supported
                result = []
                for x in dir(self):
                    if x.startswith("render_"):
                        _a, b = x.split("_", 1)
                        result.append(b)

                print "Plugin {0} is unable to produce output in format {1}. Supported formats are {2}. Please send a feature request".format(self.__class__.__name__, config.OUTPUT, result)
                return

            ## Try to call it using our renderer
            func(self, data, renderer())

        func(outfd, data)

## Event handlers do stuff in response to certain events
class EventHandler:
    def startup(self):
        """ This method gets called after all options are parsed, but
        before commands are executed
        """
