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
from ce1sus_api.api.ce1susapi import Ce1susAPI, Ce1susAPIException, Ce1susAPIConnectionException


# pylint: disable=R0904,R0201
class TestConnection(unittest.TestCase):
  """Unit test for connections"""

  URL = 'http://dontexist:8080/REST/0.2.0'

  def test_noconnection_wrong_url(self):
    """Tests if there is a connection with the wrong url"""
    api = Ce1susAPI('http://dontexist:8080/REST/0.2.0', 'SomeKey')
    try:
      api.get_event_by_uuid('774bab19-0999-444b-b699-56ff8b33c53d')
      assert False
    except Ce1susAPIConnectionException:
      assert True
    except Ce1susAPIException:
      assert False
    del api

  def test_noconnection_wrong_creds(self):
    """Tests if there is a connection with invalid credentials"""
    api = Ce1susAPI(TestConnection.URL, 'SomeKey')
    try:
      api.get_event_by_uuid('774bab19-0999-444b-b699-56ff8b33c53d')
      assert False
    except Ce1susAPIConnectionException:
      assert True
    except Ce1susAPIException:
      assert False
    del api

  def test_connection(self):
    """Tests if there is a connection with valid credentials"""
    api = Ce1susAPI(TestConnection.URL, 'a5b0f71275906a890310518e422092a10600f4ce')
    try:
      api.get_event_by_uuid('774bab19-0999-444b-b699-56ff8b33c53d')
      assert False
    except Ce1susAPIConnectionException:
      assert True
    except Ce1susAPIException:
      assert False
    del api

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
