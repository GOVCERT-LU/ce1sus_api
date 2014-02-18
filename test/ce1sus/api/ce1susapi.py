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



  def test_C7_search(self):
    try:
      attributes = list()
      # get all uuids where md5 is like this
      attributes.append({'hash_md5':'b29a4ddf98aee13f226258a8fab7d577'})
      events = self.api.searchEventsUUID(objectType='generic_file', objectContainsAttribute=attributes)
      assert len(events) == 1
      assert events[0] == '8454e6da-0c44-4617-aedb-bc8604715e7f'
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C8_search(self):
    try:
      attributes = list()
      # get all uuids where md5 is like this
      attributes.append({'hash_md5':'b29a4ddf98aee13f226258a8fab7d577'})
      filterAttributes = list()
      filterAttributes.append('mime_type')
      events = self.api.searchAttributes(objectContainsAttribute=attributes, filterAttributes=filterAttributes, withDefinition=True)

      assert len(events) == 1
      assert events[0].uuid == '8454e6da-0c44-4617-aedb-bc8604715e7f'
      assert len(events[0].objects) == 1
      assert len(events[0].objects[0].attributes) == 1
      assert events[0].objects[0].attributes[0].definition.name == 'mime_type'
    except Ce1susAPIException as e:
      print e
      assert False

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
