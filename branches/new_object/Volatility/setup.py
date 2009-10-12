#/usr/bin/env python

from distutils.core import setup
import volatility
import sys

py2exe_available = True
try:
    import py2exe #pylint: disable-msg=W0611,F0401
except ImportError:
    py2exe_available = False

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
                        "volatility.win32",
                        "memory_plugins",
                        "memory_plugins.internal",
                        "memory_plugins.registry",
                        "memory_objects",
                        "memory_objects.Windows",
                        ]

if py2exe_available:
    py2exe_distdir = 'dist/py2exe'
    opts['console'] = [{ 'script': 'volatility.py',
#                          'icon_resources': [(1, 'resources/py.ico')]
                      }]
    opts['options'] = {'py2exe':{'optimize': 2,
                                 'dist_dir': py2exe_distdir,
                                 'packages': opts['packages'],
                                }
                      }

distrib = setup(**opts)

if 'py2exe' in sys.argv:
    # Any py2exe specific files or things that need doing can go in here
    pass