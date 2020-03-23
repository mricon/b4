#!/usr/bin/env python3

import os
import b4
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


NAME = 'b4'

setup(
    version=b4.VERSION,
    url='https://git.kernel.org/pub/scm/utils/b4/b4.git',
    name=NAME,
    description='A tool to work with public-inbox and patch archives',
    author='Konstantin Ryabitsev',
    author_email='mricon@kernel.org',
    packages=['b4'],
    license='GPLv2+',
    long_description=read('man/b4.5.rst'),
    long_description_content_type='text/x-rst',
    keywords=['git', 'lore.kernel.org', 'patches'],
    install_requires=[
        'requests'
    ],
    python_requires='>=3.6',
    entry_points={
        'console_scripts': [
            'b4=b4.command:cmd'
        ],
    },
)
