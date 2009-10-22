""" This UI Defines a suitable XML schema to be exportable to other tools.

"""

## FIXME - this is currently very rough - we need to discuss how we
## export, what needs to be exported and what schema to use.
import xml.etree.cElementTree as etree
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
                     name = kwargs.get('name','table'),
                     format = kwargs.get('format'))

