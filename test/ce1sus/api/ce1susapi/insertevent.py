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
from ce1sus.api.ce1susapi import Ce1susAPI, Ce1susAPIException, Ce1susForbiddenException
from ce1sus.api.restclasses import RestEvent, RestObject, RestObjectDefinition, RestAttribute, RestAttributeDefinition
from dagr.helpers.strings import stringToDateTime
from dagr.helpers.objects import compareObjects


# pylint:disable=R0904, R0201
class TestInsertEvent(unittest.TestCase):

  URL = 'http://localhost:8080/REST/0.2.0'
  APIKEY = 'b5543a8ce54937b6230e276772add8af136b07e1'

  @staticmethod
  def __generateEvent1():
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
    obj.children = None

    # object Attributes

    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.name = 'file_name'
    attribute.definition.description = 'The file_name field specifies the name of the file.'
    attribute.definition.regex = '^.+$'
    attribute.definition.class_index = 1
    attribute.definition.handler_index = 6
    attribute.definition.attributes = None
    attribute.definition.chksum = 'beba24a09fe92b09002616e6d703b3a14306fed1'
    attribute.value = 'MaliciousTest.exe'
    attribute.ioc = 1

    obj.attributes.append(attribute)

    child = RestObject()
    child.definition = RestObjectDefinition()
    child.definition.name = 'forensic_records'
    child.definition.description = 'forensic_records'
    child.definition.chksum = 'fc771f573182da23515be31230903ec2c45e8a3a'
    child.attributes = list()
    child.parent = None
    child.children = None

    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.name = 'description'
    attribute.definition.description = 'Contains free text description for an object'
    attribute.definition.regex = '^.+$'
    attribute.definition.class_index = 0
    attribute.definition.handler_index = 10
    attribute.definition.chksum = '408ae68eee4c289d0aac277963787374ff5ad137'
    attribute.value = 'This is a description!'
    attribute.ioc = 0

    child.attributes.append(attribute)

    event.objects.append(child)
    event.objects.append(obj)

    return event

  @staticmethod
  def generate_event2():
    event = TestInsertEvent.__generateEvent1()
    event.objects[0].children = list()
    child = RestObject()
    child.definition = RestObjectDefinition()
    child.definition.name = 'forensic_records'
    child.definition.description = 'forensic_records'
    child.definition.chksum = 'fc771f573182da23515be31230903ec2c45e8a3a'
    child.attributes = list()
    child.parent = None
    child.children = None

    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.name = 'description'
    attribute.definition.description = 'Contains free text description for an object'
    attribute.definition.regex = '^.+$'
    attribute.definition.class_index = 0
    attribute.definition.handler_index = 10
    attribute.definition.chksum = '408ae68eee4c289d0aac277963787374ff5ad137'
    attribute.value = 'This is a description of a child!'
    attribute.ioc = 0

    child.attributes.append(attribute)

    event.objects[0].children.append(child)
    return event

  def setUp(self):
    self.api = Ce1susAPI(TestInsertEvent.URL, TestInsertEvent.APIKEY)

  """"
  def test_authorized_insert(self):

    try:
      event = TestInsertEvent.__generateEvent1()
      return_event = self.api.insertEvent(event, True)
      uuid = return_event.uuid
      return_event.uuid = None
      assert compareObjects(return_event, event)
      return_event.uuid = uuid
      get_event = self.api.getEventByUUID(uuid, withDefinition=True)
      assert compareObjects(return_event, get_event)

    except Ce1susAPIException as e:
      print e
      assert False

  def test_authorized_insert_withChild(self):

    try:
      event = TestInsertEvent.generate_event2()
      return_event = self.api.insertEvent(event, True)
      uuid = return_event.uuid
      return_event.uuid = None
      assert compareObjects(return_event, event)
      return_event.uuid = uuid
      get_event = self.api.getEventByUUID(uuid, withDefinition=True)
      assert compareObjects(return_event, get_event)

    except Ce1susAPIException as e:
      print e
      assert False

  def test_authorized_insert_with_special_chars(self):
    event = TestInsertEvent.__generateEvent1()
    event.title = 'TitleWithSpecialChar' + u'\u2019'
    event.uuid = None
    return_event = self.api.insertEvent(event, True)
    uuid = return_event.uuid
    return_event.uuid = None
    assert compareObjects(return_event, event)
    return_event.uuid = uuid
    get_event = self.api.getEventByUUID(uuid, withDefinition=True)
    assert (compareObjects(return_event, get_event))

  def test_unauthorized_insert(self):
    api = Ce1susAPI(TestInsertEvent.URL, 'SomeKey')
    try:
      event = TestInsertEvent.__generateEvent1()
      api.insertEvent(event)
      assert False
    except Ce1susForbiddenException:
      assert True
    except Ce1susAPIException as e:
      print e
      assert False

  """
  def test_authorized_insert_with_file(self):
    try:
      event = TestInsertEvent.__generateEvent1()
      attribute = RestAttribute()
      attribute.definition = RestAttributeDefinition()
      attribute.definition.chksum = '03c710c3265fe4488f559ebda358beb63525bda3'
      attribute.value = ('TestFile.txt', 'IAphc2RhZmFzZmQ=')
      attribute.ioc = 0
      event.objects[1].attributes.append(attribute)
      return_event = self.api.insertEvent(event, False)
      uuid = return_event.uuid
      return_event.uuid = None
      assert compareObjects(return_event, event)
      return_event.uuid = uuid
      get_event = self.api.getEventByUUID(uuid, withDefinition=False)
      assert compareObjects(return_event, get_event)

    except Ce1susAPIException as e:
      print e
      assert False
