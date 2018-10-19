#!/usr/bin/env python

__author__ = "Andrea Fioraldi"
__copyright__ = "Copyright 2017, Andrea Fioraldi"
__license__ = "BSD 2-Clause"
__email__ = "andreafioraldi@gmail.com"

from setuptools import setup

VER = "1.0.7"

setup(
    name='angrdbg',
    version=VER,
    license=__license__,
    description='Abstract library to generate angr states from a debugger state',
    author=__author__,
    author_email=__email__,
    url='https://github.com/andreafioraldi/angrdbg',
    download_url = 'https://github.com/andreafioraldi/angrdbg/archive/' + VER + '.tar.gz',
    package_dir={'angrdbg': 'angrdbg'},
    packages=['angrdbg'],
    install_requires=['angr', 'rpyc', 'ipython'],
    entry_points={
        'console_scripts': ['angrdbg_srv = angrdbg.server:main']
    },
)
