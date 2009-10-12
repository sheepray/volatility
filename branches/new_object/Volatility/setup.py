#/usr/bin/env python

from distutils.core import setup
import volatility
import sys
import os
import glob

py2exe_available = True
try:
    import py2exe #pylint: disable-msg=W0611,F0401
except ImportError:
    py2exe_available = False

def find_py_files(topdirs):
    ret = []
    for topdir in topdirs:
        for r, ds, fs in os.walk(topdir):
            ret.append((r, [ os.path.join(r, f) for f in fs if f.endswith('.py')]))
    return ret

opts = {}

opts['name']         = "volatility"
opts['version']      = volatility.version
opts['description']  = "Volatility -- Volatile memory framwork"
opts['author']       = "AAron Walters"
opts['author_email'] = "awalters@volatilesystems.com"  
opts['url']          = "http://www.volatilesystems.com"
opts['license']      = "GPL"
opts['scripts']      = ["volatility.py"]
opts['packages']     = ["volatility",
                        "volatility.win32"]
opts['data_files']   = find_py_files(['memory_plugins',
                                      'memory_objects'])

if py2exe_available:
    py2exe_distdir = 'dist/py2exe'
    opts['console'] = [{ 'script': 'volatility.py',
#                          'icon_resources': [(1, 'resources/py.ico')]
                      }]
    opts['options'] = {'py2exe':{'optimize': 2,
                                 'dist_dir': py2exe_distdir,
                                 'packages': opts['packages'] + ['socket', 'ctypes', 'Crypto.Cipher'],
                                 # This, along with zipfile = None, ensures a single binary
                                 'bundle_files': 1,
                                }
                      }
    opts['zipfile'] = None

distrib = setup(**opts)

if 'py2exe' in sys.argv:
    # Any py2exe specific files or things that need doing can go in here
    pass