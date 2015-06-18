from distutils.core import setup
import py2exe, sys, os

sys.path.append('libs')
from mnemonic import Mnemonic
from bip32utils.BIP32Key import *
import ed25519djb as ed25519
import hashlib
import base58

sys.argv.append('py2exe')

setup(
    options = {'py2exe': {'bundle_files': 1, 'compressed': True}},
    console = ['factoidGenesisManager.py'],
    zipfile = None,
)
