# -*- coding: utf-8 -*-

"""
(Description)

Created on Oct 29, 2013
"""

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'

import unittest
from ce1sus.api.ce1susapi import Ce1susAPI, Ce1susAPIException, Ce1susForbiddenException, Ce1susNothingFoundException, Ce1susAPIConnectionException, Ce1susInvalidParameter, Ce1susForbiddenException, Ce1susUnkownDefinition
from ce1sus.api.restclasses import RestEvent, RestObject, RestObjectDefinition, RestAttribute, RestAttributeDefinition
from dagr.helpers.datumzait import datumzait
from dagr.helpers.objects import compareObjects, printObject
from dagr.helpers.strings import stringToDateTime
from datetime import datetime


# pylint:disable=R0904
class TestAPI(unittest.TestCase):

  # URL = 'https://ce1sus-dev.int.govcert.etat.lu/REST/0.2.0'
  URL = 'http://localhost:8080/REST/0.2.0'
  APIKEY = '646a4ed8aa4808a548835f7b4640280abfa2d289'

  def setUp(self):
    self.api = Ce1susAPI(TestAPI.URL, TestAPI.APIKEY)

  def tearDown(self):
    pass





if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
