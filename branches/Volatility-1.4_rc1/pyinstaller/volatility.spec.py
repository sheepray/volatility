# -*- mode: python -*-
projpath = os.path.dirname(os.path.dirname(os.path.abspath(SPEC)))

def get_plugins(list):
    for item in list:
        if item[0].startswith('volatility.plugins') and not (item[0] == 'volatility.plugins' and '__init__.py' in item[1]):
            yield item

a = Analysis([os.path.join(HOMEPATH, 'support/_mountzlib.py'),
              os.path.join(HOMEPATH, 'support/useUnicode.py'),
              os.path.join(projpath, 'volatility.py')],
              pathex = [HOMEPATH],
              hookspath = [os.path.join(projpath, 'pyinstaller')])
pyz = PYZ(a.pure - set(get_plugins(a.pure)),
          name = os.path.join(projpath, 'pyinstaller', 'build', 'vol.pkz'))
plugins = Tree(os.path.join(projpath, 'volatility', 'plugins'),
               os.path.join('plugins'))
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          plugins,
          name = os.path.join('dist', 'volatility'),
          debug = False,
          strip = False,
          upx = True,
          console = 1)
