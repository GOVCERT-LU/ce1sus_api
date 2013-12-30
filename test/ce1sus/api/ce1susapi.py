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
from ce1sus.api.ce1susapi import Ce1susAPI, Ce1susAPIException, Ce1susForbiddenException, Ce1susNothingFoundException, Ce1susAPIConnectionException, Ce1susInvalidParameter
from ce1sus.api.restclasses import RestEvent, RestObject, RestObjectDefinition, RestAttribute, RestAttributeDefinition
from dagr.helpers.datumzait import datumzait
from dagr.helpers.objects import compareObjects
from dagr.helpers.string import stringToDateTime
from datetime import datetime


# pylint:disable=R0904
class TestAPI(unittest.TestCase):

  URL = 'https://ce1sus-dev.int.govcert.etat.lu/REST/0.2.0'
  # URL = 'http://localhost:8080/REST/0.2.0'
  APIKEY = '646a4ed8aa4808a548835f7b4640280abfa2d289'

  def setUp(self):
    self.api = Ce1susAPI(TestAPI.URL, TestAPI.APIKEY)

  def tearDown(self):
    pass

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
    attribute.definition.chksum = '9802f41df84b79d361e9aafe62386299a77c76f8'
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
    attribute.definition.chksum = 'b248f7d94db2e4da5188d7d8ba242f23ba733012'
    attribute.value = 'This is a description!'
    attribute.ioc = 0

    obj.children.append(child)
    event.objects.append(obj)

    child.attributes.append(attribute)

    return event

  def test_A_noconnection(self):
    api = Ce1susAPI('http://dontexist:8080/REST/0.2.0', 'SomeKey')
    try:

      api.getEventByUUID('9e299a5a-9591-4f11-a51f-8d0d11d37f80')
      assert False
    except Ce1susAPIConnectionException:
      assert True
    except Ce1susAPIException:
      assert False
    del api

  def test_B_Unauthorized_Get(self):
    api = Ce1susAPI(TestAPI.URL, 'SomeKey2')
    try:
      api = Ce1susAPI(TestAPI.URL, 'SomeKey2')
      api.getEventByUUID('9e299a5a-9591-4f11-a51f-8d0d11d37f80')
      assert False
    except Ce1susForbiddenException:
      assert True
    except Ce1susAPIException:
      assert False
    del api

  def test_B_Unauthorized_insert(self):
    api = Ce1susAPI(TestAPI.URL, 'SomeKey')
    try:

      event = TestAPI.__generateEvent()
      api.insertEvent(event)
      assert False
    except Ce1susForbiddenException:
      assert True
    except Ce1susAPIException as e:
      print e
      assert False
    del api

  def test_C1_Authorized_Get_InvalidUUID(self):
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

  def test_C1b_Authorized_Get_NotFound(self):
    try:
      # this is a valid uuid but not found
      self.api.getEventByUUID('32016ddc-1b61-41e7-a563-2d9e27ad798b')
      assert False
    except Ce1susNothingFoundException:
      assert True
    except Ce1susInvalidParameter:
      assert False
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C2_Authorized_insert(self):

    try:
      event = TestAPI.__generateEvent()
      returnEvent = self.api.insertEvent(event, True)
      uuidValue = returnEvent.uuid
      returnEvent = self.api.getEventByUUID(uuidValue, withDefinition=True)
      returnEvent.uuid = None
      assert (compareObjects(event, returnEvent))
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C3_Authorized_Insert_SpecialChars(self):
    try:
     event = TestAPI.__generateEvent()
     event.title = 'TitleWithSpecialChar' + u'\u2019'
     event.uuid = None
     returnEvent = self.api.insertEvent(event, True)
     uuidValue = returnEvent.uuid
     returnEvent = self.api.getEventByUUID(uuidValue, withDefinition=True)
     returnEvent.uuid = None
     assert (compareObjects(event, returnEvent))
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C4_Authorized_getEvents(self):
    try:
     events = self.api.getEvents()
     # just checking if the number of events is as expected
     assert len(events) == 16
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C5_Authorized_getEvents(self):
    try:
      uuidlist = ['c26a2e2a-655f-452b-b2b7-30aea2f7d1cc', '37cda72e-0729-488e-bb45-11d11fcfc41a', 'cebe6f4b-56a1-40f9-8e16-577c94c16343']
      events = self.api.getEvents(uuids=uuidlist)
      # just checking if the number of events is as expected
      assert len(events) == 3
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C5_Authorized_getDefinitions(self):
    try:
     adefinitions = self.api.getAttributeDefinitions()
     odefinitions = self.api.getObjectDefinitions()
     assert len(adefinitions) == 103
     assert len(odefinitions) == 12
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C5b_Authorized_getEvents(self):
    try:
      uuidlist = ['c26a2e2a-655f-452b-b2b7-30aea2f7d1cc', '37cda72e-0729-488e-bb45-11d11fcfc41a', 'cebe6f4b-56a1-40f9-8e16-577c94c16343']
      events = self.api.getEvents(uuids=uuidlist, offset=0,
                limit=1)
      # just checking if the number of events is as expected
      assert len(events) == 1
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C5c_Authorized_getEvents(self):
    try:
      uuidlist = ['c26a2e2a-655f-452b-b2b7-30aea2f7d1cc', '37cda72e-0729-488e-bb45-11d11fcfc41a', 'cebe6f4b-56a1-40f9-8e16-577c94c16343']
      events = self.api.getEvents(uuids=uuidlist, offset=1,
                limit=1)
      # just checking if the number of events is as expected
      assert len(events) == 1
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C5d_Authorized_getEvents(self):
    try:
      uuidlist = ['c26a2e2a-655f-452b-b2b7-30aea2f7d1cc', '37cda72e-0729-488e-bb45-11d11fcfc41a', 'cebe6f4b-56a1-40f9-8e16-577c94c16343']
      events = self.api.getEvents(uuids=uuidlist, offset=3,
                limit=1)
      # just checking if the number of events is as expected
      assert len(events) == 0
    except Ce1susAPIException as e:
      print e
      assert False

  def test_C5d_Authorized_getEvents(self):
    try:
      uuidlist = ['c26a2e2a-655f-452b-b2b7-30aea2f7d1cc', '37cda72e-0729-488e-bb45-11d11fcfc41a', 'cebe6f4b-56a1-40f9-8e16-577c94c16343']
      events = self.api.getEvents(uuids=uuidlist, startDate=datetime.now())
      # just checking if the number of events is as expected
      assert len(events) == 0
    except Ce1susAPIException as e:
      print e
      assert False

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
