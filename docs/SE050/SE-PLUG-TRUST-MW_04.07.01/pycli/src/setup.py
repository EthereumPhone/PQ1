#
# Copyright 2018-2020,2025 NXP
# SPDX-License-Identifier: Apache-2.0
#

from setuptools import setup
import sys
import os
try:
    import py2exe
except ImportError:
    pass

sys.path.append(os.path.abspath(os.path.dirname(__file__) + os.sep + "sss"))

try:
    import cli
    import sss
except ImportError:
    pass

try:
    import plugandtrust_ver as plugandtrust_ver
except ImportError:
    class plugandtrust_ver(object):
        PLUGANDTRUST_MAJOR=3
        PLUGANDTRUST_MINOR=0
        PLUGANDTRUST_DEV=1

tools_dir = os.path.abspath(os.path.dirname(__file__) \
    + os.sep + ".." \
    + os.sep + ".." \
    + os.sep + "tools")

if tools_dir == r"C:\tools":
    data_files = []
else:
    data_files = [(tools_dir, ["libsssapisw.dll",
            "libsssapisw.dylib"]),]

setup(
    name='ssscli',
    version='%d.%d.%d'%(
        int(plugandtrust_ver.PLUGANDTRUST_MAJOR),
        int(plugandtrust_ver.PLUGANDTRUST_MINOR),
        int(plugandtrust_ver.PLUGANDTRUST_DEV)),
    py_modules=['ssscli'],
    options={
        'py2exe': {
            'packages': [
                'cffi',
                'click',
                'cryptography',
            ],
        }
    },

    install_requires=[
        'cffi',
        'click',
        'cryptography',
    ],
    entry_points='''
        [console_scripts]
        ssscli=cli.cli:cli
    ''',
    console=[
        'pySSSCLI.py',
        'Provision/Provision_GCP.py',
        'Provision/Provision_IBM.py',
        'Provision/Provision_AZURE.py',
        'Provision/Provision_AWS.py',
        ],
    data_files=data_files,
)
