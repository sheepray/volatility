'''
Created on 13 Oct 2009

@author: Mike Auty
'''

import re
import sre_constants
import pefile
import procdump
import volatility.win32 as win32
import volatility.obj as obj
import volatility.utils as utils
import volatility.conf as conf
config = conf.ConfObject()

ver_types = {
'_IMAGE_RESOURCE_DIRECTORY' : [ 0x12, {
  'Characteristics' : [ 0x0, ['unsigned long']],
  'Timestamp' : [ 0x4, ['unsigned long']],
  'MajorVersion': [ 0x8, ['unsigned short']],
  'Minorversion': [ 0xa, ['unsigned short']],
  'NamedEntriesCount': [ 0xc, ['unsigned short']],
  'IdEntriesCount': [0xe, ['unsigned short']],
  'Entries': [0x10, ['array', lambda x: x.NamedEntriesCount + x.IdEntriesCount, ['_IMAGE_RESOURCE_DIRECTORY_ENTRY']]], 
} ],
'_IMAGE_RESOURCE_DIRECTORY_ENTRY': [0x8, {
  'Name' : [ 0x0, ['unsigned long']],
  'DataOffset' : [ 0x4, ['unsigned long']],                                           
} ],
'_IMAGE_RESOURCE_DATA_ENTRY' : [0x10, {
  'Offset' : [0x0, ['unsigned long']],
  'Size' : [0x4, ['unsigned long']],
  'CodePage' : [0x8, ['unsigned long']],
  'Reserved' : [0xc, ['unsigned long']],                                  
} ],
'_IMAGE_RESOURCE_DIR_STRING_U' : [0x4, {
  'Length': [0x0, ['unsigned short']],
  'Value' : [0x2, ['array', lambda x: x.Length, ['unsigned short']]],
} ],
}

resource_types = { 
 'RT_CURSOR'       : 1,
 'RT_BITMAP'       : 2,
 'RT_ICON'         : 3,
 'RT_MENU'         : 4,
 'RT_DIALOG'       : 5,
 'RT_STRING'       : 6,
 'RT_FONTDIR'      : 7,
 'RT_FONT'         : 8,
 'RT_ACCELERATOR'  : 9,
 'RT_RCDATA'       : 10,
 'RT_MESSAGETABLE' : 11,
 'RT_GROUP_CURSOR' : 12,
 'RT_GROUP_ICON'   : 14,
 'RT_VERSION'      : 16,
 'RT_DLGINCLUDE'   : 17,
 'RT_PLUGPLAY'     : 19,
 'RT_VXD'          : 20,
 'RT_ANICURSOR'    : 21,
 'RT_ANIICON'      : 22,
 'RT_HTML'         : 23,
}

class verinfo(procdump.procexedump):
    """Prints out the version information from PE images"""
    
    def __init__(self, *args): 
        procdump.procexedump.__init__(self, *args)
        config.remove_option("OFFSET")
        config.remove_option("PIDS")
        config.add_option("OFFSET", short_option="o", type='int',
                          help="Offset of the module to print the version information for")
        config.add_option('PATTERN', short_option="p", default=None,
                          help='dump modules matching REGEX')
        config.add_option('IGNORE_CASE', short_option='i', action='store_true',
                      help='ignore case in pattern match', default=False)
    
    def calculate(self):
        """Returns a unique list of modules"""
        addr_space = utils.load_as()
        addr_space.profile.add_types(ver_types)

        if config.PATTERN is not None:
            try:
                if config.IGNORE_CASE:
                    module_pattern = re.compile(config.PATTERN, flags=sre_constants.SRE_FLAG_IGNORECASE)
                else:
                    module_pattern = re.compile(config.PATTERN)
            except sre_constants.error, e:
                config.error('Regular expression parsing error: %s' % e)

        if config.OFFSET is not None:
            if not addr_space.is_valid_address(config.OFFSET):
                config.error("Specified offset is not valid for the provided address space")
            yield addr_space, config.OFFSET
            raise StopIteration
        
        tasks = win32.tasks.pslist(addr_space)

        for task in tasks:
            for m in self.list_modules(task):
                if config.PATTERN is not None:
                    if not (module_pattern.search(str(m.FullDllName)) 
                            or module_pattern.search(str(m.ModuleName))):
                        continue
                        
                yield task.get_process_address_space(), m

    def get_section_name(self, section):
        """Returns the null-terminated section name"""
        array = ''.join([chr(x) for x in section.Name]) + "\x00"
        return array[:array.index("\x00")]

    def render_text(self, outfd, data):
        """Renders the text"""
        for s, m in data:
            outfd.write(str(m.FullDllName))
            outfd.write("\n")
            if not s.is_valid_address(m.BaseAddress):
                outfd.write("  Disk image not resident in memory\n")
                continue
            
            # Using pefile is probably cheating a bit, and the initial elements
            # of a new object resource reader are present (_IMAGE_RESOURCE_DIRECTORY, etc)
            # So perhaps one day we can convert this over, but for now, we'll just build the image
            # then analyze it
            data = ""
            debugmsg = obj.NoneObject()
            if config.DEBUG > 2:
                debugmsg = outfd
            for o, c in self.get_image(debugmsg, s, m.BaseAddress):
                if len(data) < o:
                    data = data + ("\x00" * (o - len(data))) + c
                else:
                    data = data[:o] + c + data[o + len(c):]
            try:
                pedata = pefile.PE(data=data) 
                
                output = {}
                if hasattr(pedata, 'FileInfo'):
                    for entry in pedata.FileInfo:
                        if hasattr(entry, 'StringTable'):
                            for st_entry in entry.StringTable:
                                for key, val in st_entry.entries.items():
                                    aval = val.encode("ascii",'backslashreplace')
                                    output[key] = aval
                for key in output:
                    outfd.write("  " + key + " : " + output[key] + "\n")
            except pefile.PEFormatError,e:
                outfd.write("  Unable to read PE information from module\n")
