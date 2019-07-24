#!/usr/bin/env python
# -*- coding: utf-8 -*-

# IxNetwork API Bindings
#
# Copyright 1997 - 2019 by IXIA Keysight
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

from setuptools import setup
import os

def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as fn:
        return fn.read()

setup(
   name='IxNetwork',
   version='9.00.1915.16',
   description='IxNetwork Low Level API',
   long_description=read('README.rst'),
   url='https://github.com/ixiacom/ixnetwork-api-py',
   author='Ixia',
   author_email='diana.galan@keysight.com',
   packages = ['IxNetwork'],
   package_data = { 'IxNetwork': ['requirements.txt'] },
   install_requires=[
        'backports.ssl>=0.0.9'
        'backports.ssl-match-hostname>=3.5.0.1',
        'pyopenssl>=17.5.0',
        'requests>=2.18.4',
        'websocket-client>=0.47.0',
        ],
   license='License :: OSI Approved :: MIT License',
   classifiers=[
      'Development Status :: 5 - Production/Stable',
      'License :: OSI Approved :: MIT License',
      'Intended Audience :: Information Technology',
      'Intended Audience :: System Administrators',
      'Intended Audience :: Developers',
      'Environment :: No Input/Output (Daemon)',
      'Programming Language :: Python :: 2',
      'Programming Language :: Python :: 2.7',
      'Programming Language :: Python :: 3',
      'Programming Language :: Python :: 3.3',
      'Programming Language :: Python :: 3.4',
      'Programming Language :: Python :: 3.5',
      'Programming Language :: Python :: 3.6',
      'Programming Language :: Python :: 3.7',
      'Topic :: Software Development :: Libraries :: Python Modules',
      'Topic :: System :: Distributed Computing',
      'Operating System :: Microsoft :: Windows',
      'Operating System :: POSIX',
      'Operating System :: Unix',
      'Operating System :: MacOS',
   ],
   keywords='ixia ixnetwork',
   platforms=['Windows', 'Linux', 'Solaris', 'Mac OS-X', 'Unix'],
   test_suite='tests',
   zip_safe=True
)
