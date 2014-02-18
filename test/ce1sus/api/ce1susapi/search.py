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
from ce1sus.api.ce1susapi import Ce1susAPI, Ce1susAPIException, Ce1susNothingFoundException, Ce1susInvalidParameter, Ce1susForbiddenException


# pylint:disable=R0904,R0201
class TestGetEvent(unittest.TestCase):

  URL = 'http://localhost:8080/REST/0.2.0'
  APIKEY = 'b5543a8ce54937b6230e276772add8af136b07e1'

  def setUp(self):
    self.api = Ce1susAPI(TestGetEvent.URL, TestGetEvent.APIKEY)

  def test_search(self):
    try:
      attributes = list()
      # get all uuids where md5 is like this
      attributes.append({'hash_md5': '4e8d220388770a31ec036a88ba6f62b5'})
      events = self.api.searchEventsUUID(objectType='generic_file', objectContainsAttribute=attributes)
      assert len(events) == 1
      assert events[0] == 'f66290ee-8cbb-49a0-846f-e64074f1937b'
    except Ce1susAPIException as e:
      print e
      assert False
