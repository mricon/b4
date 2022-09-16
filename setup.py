#!/usr/bin/env python3

import os
import re
from setuptools import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...


def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


def find_version(source):
    version_file = read(source)
    version_match = re.search(r"^__VERSION__ = ['\"]([^'\"]*)['\"]", version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


NAME = 'b4'

setup(
    version=find_version('b4/__init__.py'),
    url='https://git.kernel.org/pub/scm/utils/b4/b4.git/tree/README.rst',
    project_urls={
        'Community': 'https://lore.kernel.org/tools'
    },
    name=NAME,
    description='A tool to work with public-inbox and patch archives',
    author='Konstantin Ryabitsev',
    author_email='mricon@kernel.org',
    packages=['b4'],
    license='GPLv2+',
    long_description=read('man/b4.5.rst'),
    long_description_content_type='text/x-rst',
    data_files=[('share/man/man5', ['man/b4.5'])],
    keywords=['git', 'public-inbox', 'lore.kernel.org', 'patches'],
    install_requires=[
        'requests>=2.24,<3.0',
        'dnspython>=2.1,<3.0',
        'dkimpy>=1.0,<2.0',
        'patatt>=0.6,<2.0',
        'git-filter-repo>=2.30,<3.0',
    ],
    python_requires='>=3.8',
    entry_points={
        'console_scripts': [
            'b4=b4.command:cmd'
        ],
    },
)
