# -*- coding: utf-8 -*-

"""
(Description)

Created on Feb 18, 2014
"""

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


import unittest
from ce1sus_api.api.ce1susapi import Ce1susAPI, Ce1susAPIException, Ce1susNothingFoundException, Ce1susInvalidParameter, Ce1susForbiddenException
from ce1sus_api.api.restclasses import RestAttributeDefinition, RestObjectDefinition


# pylint:disable=R0904,R0201
class TestInsertDefinitons(unittest.TestCase):

  URL = 'http://localhost:8080/REST/0.2.0'
  APIKEY = '8494a844eca00fdebf14b18e569b817289a84583'

  def setUp(self):
    self.api = Ce1susAPI(TestInsertDefinitons.URL, TestInsertDefinitons.APIKEY)
  """
  def test_insert_attribute_definition(self):
    adefinition = RestAttributeDefinition()
    adefinition.name = 'Test_attribute'
    adefinition.description = 'test description'
    adefinition.regex = '^.+$'
    adefinition.class_index = 0
    adefinition.handler_uuid = 'dea62bf0-8deb-11e3-baa8-0800200c9a66'
    adefinition.chksum = 'b248f7d94db2e4da5188d7d8ba242f23ba733012'
    adefinition.relation = 0

    try:
      result = self.api.insertAttributeDefinition(adefinition, True)
    except Ce1susAPIException as e:
      print e
      assert False


  def test_insert_obj_def(self):
    definition = RestObjectDefinition()
    definition.name = 'test_object'
    definition.description = 'test description'
    # the checksum will be computed anyway on the server side
    definition.chksum = None
    try:
      result = self.api.insert_object_definition(definition, True)
    except Ce1susAPIException as e:
      print e
      assert False
"""
  def test_insert_obj_def_attributes(self):
    definition = RestObjectDefinition()
    definition.name = 'test_object'
    definition.description = 'test description'

    adefinition = RestAttributeDefinition()
    adefinition.name = 'Test_attribute'
    adefinition.description = 'test description'
    adefinition.regex = '^.+$'
    adefinition.class_index = 0
    adefinition.handler_uuid = 'dea62bf0-8deb-11e3-baa8-0800200c9a66'
    adefinition.relation = 0
    adefinition.share = 1

    definition.attributes = list()
    definition.attributes.append(adefinition)
    try:
      result = self.api.insert_object_definition(definition, True)
    except Ce1susAPIException as e:
      print e
      assert False

  def test_insert_definitionWithFalutyIndexes(self):
    assert False

  def test_insert_definitionWithUnkonwnUUID(self):
    assert False
