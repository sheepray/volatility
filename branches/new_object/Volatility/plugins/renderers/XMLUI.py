""" This UI Defines a suitable XML schema to be exportable to other tools.

"""

## FIXME - this is currently very rough - we need to discuss how we
## export, what needs to be exported and what schema to use.
import volatility.UI as UI
import pdb

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
    def __init__(self, headings, output, format, name=''):
        UI.Table.__init__(self, headings=headings, output=output, format=format)
        self.output.write("<collection name='{0:s}'>\n".format(name))

    def row(self, *args):
        ## Format each item according to its format string
        self.output.write("   <collection type='row'>\n")

        for i in range(len(args)):
            self.output.write("      <item name='{0:s}'>\n".format(self.headings[i]))
            try:
                ## Try to have the object format itself for XML:
                self.output.write("{0:XML}\n".format(args[i]))
            except ValueError:
                ## Nope it cant do that so use 's' formatter instead
                self.output.write("{0:s}\n".format(args[i]))
            self.output.write("      </item>\n")                
        self.output.write("   </collection>\n")

    def __del__(self):
        self.output.write("</collection>\n")    

class xml(UI.UI):
    """ Renders plugin output in XML. Simplifies data interchange with other tools. """
    def table(self, *args, **kwargs):
        return Table(headings = args, output = self.outfd,
                     name = kwargs.get('name','table'),
                     format = kwargs.get('format'))

