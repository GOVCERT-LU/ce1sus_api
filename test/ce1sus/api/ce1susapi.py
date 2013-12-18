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
from ce1sus.api.ce1susapi import Ce1susAPI, Ce1susAPIException, Ce1susForbiddenException, Ce1susNothingFoundException, Ce1susAPIConnectionException, Ce1susUndefinedParameter
from ce1sus.api.restclasses import RestEvent, RestObject, RestObjectDefinition, RestAttribute, RestAttributeDefinition
from dagr.helpers.datumzait import datumzait
from dagr.helpers.objects import compareObjects
from dagr.helpers.string import stringToDateTime


# pylint:disable=R0904
class TestAPI(unittest.TestCase):

  URL = 'http://ce1sus-dev.int.govcert.etat.lu:8080/REST/0.2.0'
  APIKEY = 'b5543a8ce54937b6230e276772add8af136b07e1'
  UUID = '43ecf6c4-d25b-4862-9b63-4bc17125fc70'

  def setUp(self):
    self.api = Ce1susAPI(TestAPI.URL, TestAPI.APIKEY)

  @staticmethod
  def __generateEvent():
    event = RestEvent()
    event.title = 'Test Event 1'
    event.description = 'This is a test event and has no extra meaning'
    event.first_seen = stringToDateTime('2013-12-13 14:41:01+00:00')
    event.last_seen = stringToDateTime('2013-12-13 14:41:01+00:00')
    event.tlp = 'Red'
    event.risk = 'None'
    event.analysis = 'None'
    event.objects = list()
    event.comments = list()
    event.published = 1
    event.status = 'Deleted'
    event.uuid = TestAPI.UUID

    # attach some objects
    obj = RestObject()
    obj.definition = RestObjectDefinition()
    obj.definition.name = 'executable_file'
    obj.definition.description = 'executable_file\r\n\r\nThis includes all kind of compiled code'
    obj.definition.chksum = 'f82c52727e0d45c79cd3810704314d6c08fed47a'
    obj.attributes = list()
    obj.parent = None
    obj.children = list()



    # object Attributes
    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.name = 'file_name'
    attribute.definition.description = 'The file_name field specifies the name of the file.'
    attribute.definition.regex = '^.+$'
    attribute.definition.classIndex = 1
    attribute.definition.handlerIndex = 0
    attribute.definition.chksum = '15134f8e4624e2bb95081b8a722e0ac5cfc65360'
    attribute.value = 'MaliciousTest.exe'
    attribute.ioc = 1

    obj.attributes.append(attribute)


    child = RestObject()
    child.definition = RestObjectDefinition()
    child.definition.name = 'forensic_records'
    child.definition.description = 'forensic_records'
    child.definition.dbchksum = 'fc771f573182da23515be31230903ec2c45e8a3a'
    child.attributes = list()
    child.parent = None
    child.children = list()



    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.name = 'description'
    attribute.definition.description = 'Contains free text description for an object'
    attribute.definition.regex = '^.+$'
    attribute.definition.classIndex = 0
    attribute.definition.handlerIndex = 9
    attribute.definition.chksum = 'c6dc0d16ffed78c3b7a120e0d8d02877e9acf570'
    attribute.value = 'This is a description!'
    attribute.ioc = 0

    obj.children.append(child)
    event.objects.append(obj)

    child.attributes.append(attribute)

    return event

  def test_A_noconnection(self):
    try:
      api = Ce1susAPI('http://dontexist:8080/REST/0.2.0', 'SomeKey')
      api.getEventByUUID(TestAPI.UUID)
      assert False
    except Ce1susAPIConnectionException:
      assert True
    except Ce1susAPIException:
      assert False

  def test_B_Unauthorized_Get(self):
    try:
      api = Ce1susAPI(TestAPI.URL, 'SomeKey2')
      api.getEventByUUID(TestAPI.UUID)
      assert False
    except Ce1susForbiddenException:
      assert True
    except Ce1susAPIException:
      assert False

  def test_B_Unauthorized_insert(self):
    try:
      api = Ce1susAPI(TestAPI.URL, 'SomeKey')
      event = TestAPI.__generateEvent()
      api.insertEvent(event)
      assert False
    except Ce1susForbiddenException:
      assert True
    except Ce1susAPIException:
      assert False

  def test_C1_Authorized_Get(self):
    try:
      # this is not a valid uuid
      self.api.getEventByUUID('Something')
      assert False
    except Ce1susNothingFoundException:
      assert False
    except Ce1susUndefinedParameter:
      assert True
    except Ce1susAPIException:
      assert False

  def test_C1b_Authorized_Get(self):
    try:
      # this is a valid uuid but not found
      self.api.getEventByUUID('32016ddc-1b61-41e7-a563-2d9e27ad7986 ')
      assert False
    except Ce1susNothingFoundException:
      assert True
    except Ce1susUndefinedParameter:
      assert False
    except Ce1susAPIException:
      assert False

  def test_C2_Authorized_insert(self):

    try:
      event = TestAPI.__generateEvent()
      returnEvent = self.api.insertEvent(event, True)
      assert (compareObjects(event, returnEvent))
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C2b_Authorized_Get(self):
    try:
      returnEvent = self.api.getEventByUUID(TestAPI.UUID, True)
      event = TestAPI.__generateEvent()
      # is as expected?
      assert (compareObjects(event, returnEvent))
    except Ce1susNothingFoundException:
      assert False
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C3_Authorized_Insert_SpecialChars(self):
    try:
     event = TestAPI.__generateEvent()
     event.title = 'TitleWithSpecialChar' + u'\u2019'
     event.uuid = None
     returnEvent = self.api.insertEvent(event, True)
     returnEvent.uuid = None
     assert (compareObjects(event, returnEvent))
    except Ce1susAPIException as e:
      print e
      assert False

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
