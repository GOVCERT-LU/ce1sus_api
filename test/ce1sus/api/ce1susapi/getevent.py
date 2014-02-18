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
  APIKEY = 'b5543a8ce54937b6230e276772add8af136b07e1'

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
      self.api.getEventByUUID('774bab19-0999-444b-b699-56ff8b33c53d')
      assert True
    except Ce1susForbiddenException:
      assert False
    except Ce1susAPIException:
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
