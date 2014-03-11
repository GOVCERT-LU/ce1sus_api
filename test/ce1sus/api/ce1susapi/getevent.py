# -*- coding: utf-8 -*-

"""
(Description)

Created on Feb 13, 2014
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
  APIKEY = '8494a844eca00fdebf14b18e569b817289a84583'

  def setUp(self):
    self.api = Ce1susAPI(TestGetEvent.URL, TestGetEvent.APIKEY)

  def test_unauthorized_get(self):
    api = Ce1susAPI(TestGetEvent.URL, 'TesterNoGroup')
    try:
      api.getEventByUUID('774bab19-0999-444b-b699-56ff8b33c53d')
      assert False
    except Ce1susForbiddenException:
      assert True
    except Ce1susAPIException:
      assert False
    del api

  def test_unauthorized_get_2(self):
    api = Ce1susAPI(TestGetEvent.URL, '28e857e142507b139a92ac5a2d818aa62c65faa0')
    try:
      api.getEventByUUID('774bab19-0999-444b-b699-56ff8b33c53d')
      assert False
    except Ce1susForbiddenException:
      assert True
    except Ce1susAPIException:
      assert False
    del api

  def test_authorized_Get(self):
    try:
      self.api.getEventByUUID('992d9b83-24d6-4d0d-b2d7-0fce1bed57b6')
      assert True
    except Ce1susForbiddenException:
      assert False
    except Ce1susAPIException as e:
      print e
      assert False

  def test_authorized_get_invalid_uuid(self):
    try:
      # this is not a valid uuid
      self.api.getEventByUUID('Something')
      assert False
    except Ce1susNothingFoundException:
      assert False
    except Ce1susInvalidParameter:
      assert True
    except Ce1susAPIException:
      assert False

  def test_authorized_get_not_found(self):
    try:
      # this is a valid uuid but not found
      self.api.getEventByUUID('32016ddc-1b61-41e7-a563-2d9e27ad798b')
      assert False
    except Ce1susNothingFoundException:
      assert True
    except Ce1susInvalidParameter:
      assert False
    except Ce1susAPIException:
      assert False

  def test_get_event_from_other_group(self):
    assert False

  def test_get_event_with_file(self):
    try:
      # this is a valid uuid but not found
      event = self.api.getEventByUUID('f66290ee-8cbb-49a0-846f-e64074f1937b', True)
      assert True
    except Ce1susAPIException as e:
      print e
      assert False
