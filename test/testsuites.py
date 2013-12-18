# -*- coding: utf-8 -*-

"""
(Description)

Created on Jul 11, 2013
"""

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'

import unittest
from test.ce1sus.api.ce1susapi import TestAPI


def suite():
  testSuite = unittest.TestSuite()
  testSuite.addTest(TestAPI())

  return testSuite


if __name__ == "__main__":
  runner = unittest.TextTestRunner()

  test_suite = suite()

  runner.run(test_suite)
