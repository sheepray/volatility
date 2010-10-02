import volatility.conf as conf
import os

config = conf.ConfObject()

# This causes the config.PLUGINS paths to be treated as extensions of the volatility.plugins package
# Meaning that each directory is search for module when import volatility.plugins.module is requested

__path__ = [ os.path.abspath(x) for x in config.PLUGINS.split(";") ]
