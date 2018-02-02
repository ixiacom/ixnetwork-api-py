#!/usr/bin/env python
# -*- coding: utf-8 -*-

# IxNetwork API Bindings
#
# Copyright 1997 - 2017 by IXIA
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


import tests
import unittest

import IxNetwork

class GetVersionTests(unittest.TestCase):
    def setUp(self):
        self.ixNet = IxNetwork.IxNet()
        
    def tearDown(self):
        self.ixNet = None
    
    def test_get_version(self):
        self.assertEqual(self.ixNet._version, self.ixNet.getVersion(), 'incorrect default size')

    def test_version_size(self):
        self.assertEqual(len(self.ixNet.getVersion().split('.')), 4, 'incorrect default size')           


if __name__ == '__main__':
    unittest.main()
