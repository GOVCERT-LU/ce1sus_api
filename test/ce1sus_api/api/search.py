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
from ce1sus_api.api.ce1susapi import Ce1susAPI, Ce1susAPIException


# pylint:disable=R0904,R0201
class TestSearch(unittest.TestCase):

  URL = 'http://localhost:8080/REST/0.2.0'
  APIKEY = 'a500fa6845e5d3af8577c95ca6fb4cfe26798172'

  def setUp(self):
    self.api = Ce1susAPI(TestSearch.URL, TestSearch.APIKEY)

  """
  def test_search(self):
    try:
      attributes = list()
      # get all uuids where md5 is like this
      attributes.append({'hash_md5': '4e8d220388770a31ec036a88ba6f62b5'})
      events = self.api.searchEventsUUID(objectType='generic_file', objectContainsAttribute=attributes)
      assert len(events) == 1
      assert events[0].uuid == 'f66290ee-8cbb-49a0-846f-e64074f1937b'
    except Ce1susAPIException as e:
      print e
      assert False
  """

  def test_search_attributes(self):
    try:
      attributes = list()
      # get all uuids where md5 is like this
      attributes.append({'ipv4_addr': {'value': '127', 'operator': '=='}})
      events = self.api.search_attributes(objectContainsAttribute=attributes, withDefinition=True)
      print events
      assert len(events) == 1
      assert events[0].uuid == 'f66290ee-8cbb-49a0-846f-e64074f1937b'
      assert len(events[0].objects) == 1
      assert len(events[0].objects[0].attributes) == 1
      assert events[0].objects[0].attributes[0].definition.name == 'mime_type'
    except Ce1susAPIException as e:
      print e
      assert False
