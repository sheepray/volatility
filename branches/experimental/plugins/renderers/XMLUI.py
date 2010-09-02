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

""" This UI Defines a suitable XML schema to be exportable to other tools.

"""

## FIXME - this is currently very rough - we need to discuss how we
## export, what needs to be exported and what schema to use.
import xml.etree.cElementTree as etree
import volatility.UI as UI

class Table(UI.Table):
    """ Create an XML schema similar to a Table.

    A table is basically a collection of rows. Rows are in turn an
    ordered collection of objects.

    An example schema might look like:
    <collection name='pslist'>
      <collection type='row'>
        <item name = 'Pid'>
          <object type='Ctype' offset=0x12345>
          </object>
        </item>
      </collection>
    </collection>
    """
    def __init__(self, headings, output, format, name = ''):
        UI.Table.__init__(self, headings = headings, output = output, format = format)
        self.root = etree.Element('collection', {'name': name})

    def row(self, *args):
        ## Format each item according to its format string
        collection = etree.Element("collection", {'type': 'row'})

        for i in range(len(args)):
            item = etree.Element("item", {'name': self.headings[i]})
            try:
                ## Try to have the object format itself for XML:
                rendered = args[i].render_xml()
            except AttributeError:
                ## Nope it cant do that so use 's' formatter instead
                rendered = None
            if rendered:
                item.append(rendered)
            else:
                item.text = str(args[i])
            collection.append(item)

        self.root.append(collection)

    def __del__(self):
        self.output.write(etree.tostring(self.root))

class xml(UI.UI):
    """ Renders plugin output in XML. Simplifies data interchange with other tools. """
    def table(self, *args, **kwargs):
        return Table(headings = args, output = self.outfd,
                     name = kwargs.get('name', 'table'),
                     format = kwargs.get('format'))

