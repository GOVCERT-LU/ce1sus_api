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
from test.ce1sus_api.api.connection import TestConnection
from test.ce1sus_api.api.getdefinitions import TestGetDefinitons
from test.ce1sus_api.api.getevent import TestGetEvent
from test.ce1sus_api.api.getevents import TestGetEvents
from test.ce1sus_api.api.insertdefinitions import TestInsertDefinitons
from test.ce1sus_api.api.insertevent import TestInsertEvent
from test.ce1sus_api.api.search import TestSearch


def suite():
  testSuite = unittest.TestSuite()
  testSuite.addTest(TestConnection())
  testSuite.addTest(TestGetEvent())
  testSuite.addTest(TestGetDefinitons())
  testSuite.addTest(TestGetEvents())
  testSuite.addTest(TestInsertDefinitons())
  testSuite.addTest(TestInsertEvent())
  testSuite.addTest(TestSearch())

  return testSuite


if __name__ == "__main__":
  runner = unittest.TextTestRunner()

  test_suite = suite()

  runner.run(test_suite)
