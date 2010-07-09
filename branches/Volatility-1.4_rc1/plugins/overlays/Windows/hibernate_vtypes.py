hibernate_vtypes = { \
  '_HBASE_BLOCK' : [ 0x1000, {
    'Signature' : [ 0x0, ['unsigned long']],
    'Sequence1' : [ 0x4, ['unsigned long']],
    'Sequence2' : [ 0x8, ['unsigned long']],
    'TimeStamp' : [ 0xc, ['_LARGE_INTEGER']],
    'Major' : [ 0x14, ['unsigned long']],
    'Minor' : [ 0x18, ['unsigned long']],
    'Type' : [ 0x1c, ['unsigned long']],
    'Format' : [ 0x20, ['unsigned long']],
    'RootCell' : [ 0x24, ['unsigned long']],
    'Length' : [ 0x28, ['unsigned long']],
    'Cluster' : [ 0x2c, ['unsigned long']],
    'FileName' : [ 0x30, ['array', 64, ['unsigned char']]],
    'Reserved1' : [ 0x70, ['array', 99, ['unsigned long']]],
    'CheckSum' : [ 0x1fc, ['unsigned long']],
    'Reserved2' : [ 0x200, ['array', 894, ['unsigned long']]],
    'BootType' : [ 0xff8, ['unsigned long']],
    'BootRecover' : [ 0xffc, ['unsigned long']],
} ],
  '_DUAL' : [ 0xdc, {
    'Length' : [ 0x0, ['unsigned long']],
    'Map' : [ 0x4, ['pointer', ['_HMAP_DIRECTORY']]],
    'SmallDir' : [ 0x8, ['pointer', ['_HMAP_TABLE']]],
    'Guard' : [ 0xc, ['unsigned long']],
    'FreeDisplay' : [ 0x10, ['array', 24, ['_RTL_BITMAP']]],
    'FreeSummary' : [ 0xd0, ['unsigned long']],
    'FreeBins' : [ 0xd4, ['_LIST_ENTRY']],
} ],
  '_HMAP_DIRECTORY' : [ 0x1000, {
    'Directory' : [ 0x0, ['array', 1024, ['pointer', ['_HMAP_TABLE']]]],
} ],
  '_HMAP_TABLE' : [ 0x2000, {
    'Table' : [ 0x0, ['array', 512, ['_HMAP_ENTRY']]],
} ],
  '_HMAP_ENTRY' : [ 0x10, {
    'BlockAddress' : [ 0x0, ['unsigned long']],
    'BinAddress' : [ 0x4, ['unsigned long']],
    'CmView' : [ 0x8, ['pointer', ['_CM_VIEW_OF_FILE']]],
    'MemAlloc' : [ 0xc, ['unsigned long']],
} ],
  '_CM_KEY_SECURITY_CACHE_ENTRY' : [ 0x8, {
    'Cell' : [ 0x0, ['unsigned long']],
    'CachedSecurity' : [ 0x4, ['pointer', ['_CM_KEY_SECURITY_CACHE']]],
} ],
  '_CM_KEY_SECURITY_CACHE' : [ 0x28, {
    'Cell' : [ 0x0, ['unsigned long']],
    'ConvKey' : [ 0x4, ['unsigned long']],
    'List' : [ 0x8, ['_LIST_ENTRY']],
    'DescriptorLength' : [ 0x10, ['unsigned long']],
    'Descriptor' : [ 0x14, ['_SECURITY_DESCRIPTOR_RELATIVE']],
} ],
  '_CM_CELL_REMAP_BLOCK' : [ 0x8, {
    'OldCell' : [ 0x0, ['unsigned long']],
    'NewCell' : [ 0x4, ['unsigned long']],
} ],
  '_LARGE_INTEGER' : [ 0x8, {
    'LowPart' : [ 0x0, ['unsigned long']],
    'HighPart' : [ 0x4, ['long']],
    'QuadPart' : [ 0x0, ['long long']],
} ],
    '_IMAGE_HIBER_HEADER' : [ 0xbc, { \
    'Signature' : [ 0x0, ['array', 4,['unsigned char']]], \
    'SystemTime' : [ 0x20, ['_LARGE_INTEGER']], \
    'FirstTablePage' : [ 0x58, ['unsigned long']], \
} ], \
    'MEMORY_RANGE_ARRAY_LINK' : [ 0x10, { \
    'NextTable' : [ 0x4, ['unsigned long']], \
    'EntryCount' : [ 0xc, ['unsigned long']], \
} ], \
    'MEMORY_RANGE_ARRAY_RANGE' : [ 0x10, { \
    'StartPage' : [ 0x4, ['unsigned long']], \
    'EndPage' : [ 0x8, ['unsigned long']], \
} ], \
    '_MEMORY_RANGE_ARRAY' : [ 0x20, { \
    'MemArrayLink' : [ 0x0, ['MEMORY_RANGE_ARRAY_LINK']], \
    'RangeTable': [ 0x10, ['array', lambda x: x.MemArrayLink.EntryCount,
                           ['MEMORY_RANGE_ARRAY_RANGE']]],
} ], \
  '_KGDTENTRY' : [  0x8 , { \
  'BaseLow' : [ 0x2 , ['unsigned short']], \
  'BaseMid' : [ 0x4, ['unsigned char']], \
  'BaseHigh' : [ 0x7, ['unsigned char']], \
} ], \
'_IMAGE_XPRESS_HEADER' : [  0x20 , { \
  'u09' : [ 0x9, ['unsigned char']], \
  'u0A' : [ 0xA, ['unsigned char']], \
  'u0B' : [ 0xB, ['unsigned char']], \
} ]
}