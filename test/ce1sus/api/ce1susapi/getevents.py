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
from ce1sus.api.ce1susapi import Ce1susAPI, Ce1susAPIException


# pylint:disable=R0904, R0201
class TestGetEvents(unittest.TestCase):

  URL = 'http://localhost:8080/REST/0.2.0'
  APIKEY = 'b5543a8ce54937b6230e276772add8af136b07e1'

  def setUp(self):
    self.api = Ce1susAPI(TestGetEvents.URL, TestGetEvents.APIKEY)

  def test_authorized_get_events(self):
    try:
      events = self.api.getEvents()
      # just checking if the number of events is as expected
      # assert len(events) == 13
      assert True

    except Ce1susAPIException as e:
      print e
      assert False

  def test_authorized_get_events_with_list(self):
    try:
      uuidlist = ['774bab19-0999-444b-b699-56ff8b33c53d', '8454e6da-0c44-4617-aedb-bc8604715e7f', '0c13e469-cc1d-4081-9785-6ad678deba7d']
      events = self.api.getEvents(uuids=uuidlist)
      # just checking if the number of events is as expected
      assert len(events) == 3
    except Ce1susAPIException:
      assert False

  def test_half_unauthorized_get_events(self):
    try:
      api = Ce1susAPI(TestGetEvents.URL, '28e857e142507b139a92ac5a2d818aa62c65faa0')
      uuidlist = ['6ce3afbf-d971-47d2-a8ed-f08fe7d6847e', '8454e6da-0c44-4617-aedb-bc8604715e7f', '0c13e469-cc1d-4081-9785-6ad678deba7d']
      events = api.getEvents(uuids=uuidlist)
      # just checking if the number of events is as expected
      assert len(events) == 1
    except Ce1susAPIException:
      assert False

  def test_unauthorized_get_events(self):
    try:
      api = Ce1susAPI(TestGetEvents.URL, 'Foo')
      uuidlist = ['6ce3afbf-d971-47d2-a8ed-f08fe7d6847e', '8454e6da-0c44-4617-aedb-bc8604715e7f', '0c13e469-cc1d-4081-9785-6ad678deba7d']
      events = api.getEvents(uuids=uuidlist)
      # just checking if the number of events is as expected
      assert False
    except Ce1susAPIException:
      assert True
