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


# pylint:disable=R0904,R0201
class TestGetDefinitons(unittest.TestCase):

  URL = 'http://localhost:8080/REST/0.2.0'
  APIKEY = 'b5543a8ce54937b6230e276772add8af136b07e1'

  def setUp(self):
    self.api = Ce1susAPI(TestGetDefinitons.URL, TestGetDefinitons.APIKEY)
  """
  def test_authorized_get_definitions(self):
    try:
      adefinitions = self.api.getAttributeDefinitions()
      odefinitions = self.api.get_object_definitions()
      assert len(adefinitions) == 103
      assert len(odefinitions) == 11
      assert True
    except Ce1susAPIException as e:
      print e
      assert False
  """
  def test_get_definition_without_relations(self):
    try:
      chksums = list()
      chksums.append('4ab2df0a57a74fdf904e0e27086676ed9c4c3cdf')
      odefinitions = self.api.get_object_definitions(chksums=chksums,
                                                   withDefinition=False)
      assert odefinitions
      assert len(odefinitions) == 1
      assert not odefinitions[0].attributes
    except Ce1susAPIException as e:
      print e
      assert False

  def test_get_definition_with_relations(self):
    try:
      chksums = list()
      chksums.append('4ab2df0a57a74fdf904e0e27086676ed9c4c3cdf')
      odefinitions = self.api.get_object_definitions(chksums=chksums,
                                                      withDefinition=True)
      assert odefinitions
      assert len(odefinitions) == 1
      assert len(odefinitions[0].attributes) == 7
    except Ce1susAPIException as e:
      print e
      assert False
