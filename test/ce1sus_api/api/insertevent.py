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
from ce1sus_api.api.ce1susapi import Ce1susAPI, Ce1susAPIException, Ce1susForbiddenException
from ce1sus_api.api.restclasses import RestEvent, RestObject, RestObjectDefinition, RestAttribute, RestAttributeDefinition
from ce1sus_api.helpers.strings import stringToDateTime
from ce1sus_api.helpers.objects import compare_objects


# pylint:disable=R0904, R0201
class TestInsertEvent(unittest.TestCase):

  URL = 'http://localhost:8080/REST/0.2.0'
  APIKEY = '8494a844eca00fdebf14b18e569b817289a84583'

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
    event.group = 'Default_Group'

    # attach some objects
    obj = RestObject()
    obj.definition = RestObjectDefinition()
    obj.definition.name = 'executable_file'
    obj.definition.description = 'executable_file\r\n\r\nThis includes all kind of compiled code'
    obj.definition.chksum = 'f82c52727e0d45c79cd3810704314d6c08fed47a'
    obj.attributes = list()
    obj.parent = None
    obj.children = None
    obj.author = 'Default_Group'

    # object Attributes

    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.name = 'file_name'
    attribute.definition.description = 'The file_name field specifies the name of the file.'
    attribute.definition.regex = '^.+$'
    attribute.definition.class_index = 1
    attribute.definition.handler_uuid = '08645c00-8dec-11e3-baa8-0800200c9a66'
    attribute.definition.attributes = None
    attribute.definition.chksum = 'beba24a09fe92b09002616e6d703b3a14306fed1'
    attribute.value = 'MaliciousTest.exe'
    attribute.ioc = 1
    attribute.author = 'Default_Group'

    obj.attributes.append(attribute)

    child = RestObject()
    child.definition = RestObjectDefinition()
    child.definition.name = 'forensic_records'
    child.definition.description = 'forensic_records'
    child.definition.chksum = 'fc771f573182da23515be31230903ec2c45e8a3a'
    child.attributes = list()
    child.parent = None
    child.children = None
    child.author = 'Default_Group'

    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.name = 'description'
    attribute.definition.description = 'Contains free text description for an object'
    attribute.definition.regex = '^.+$'
    attribute.definition.class_index = 0
    attribute.definition.handler_uuid = '1a8ec7d0-8dec-11e3-baa8-0800200c9a66'
    attribute.definition.chksum = '408ae68eee4c289d0aac277963787374ff5ad137'
    attribute.value = 'This is a description!'
    attribute.ioc = 0
    attribute.author = 'Default_Group'

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
    child.author = 'Default_Group'

    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.name = 'description'
    attribute.definition.description = 'Contains free text description for an object'
    attribute.definition.regex = '^.+$'
    attribute.definition.class_index = 0
    attribute.definition.handler_uuid = '1a8ec7d0-8dec-11e3-baa8-0800200c9a66'
    attribute.definition.chksum = '408ae68eee4c289d0aac277963787374ff5ad137'
    attribute.value = 'This is a description of a child!'
    attribute.ioc = 0
    attribute.author = 'Default_Group'

    child.attributes.append(attribute)

    event.objects[0].children.append(child)
    return event

  def setUp(self):
    self.api = Ce1susAPI(TestInsertEvent.URL, TestInsertEvent.APIKEY)

  def test_authorized_insert(self):

    try:
      event = TestInsertEvent.__generateEvent1()
      return_event = self.api.insert_event(event, True)
      uuid = return_event.uuid
      return_event.uuid = None
      assert compare_objects(return_event, event)
      return_event.uuid = uuid
      get_event = self.api.get_event_by_uuid(uuid, withDefinition=True)
      assert compare_objects(return_event, get_event)

    except Ce1susAPIException as e:
      print e
      assert False

  def test_authorized_insert_withChild(self):

    try:
      event = TestInsertEvent.generate_event2()
      return_event = self.api.insert_event(event, True)
      uuid = return_event.uuid
      return_event.uuid = None
      assert compare_objects(return_event, event)
      return_event.uuid = uuid
      get_event = self.api.get_event_by_uuid(uuid, withDefinition=True)
      assert compare_objects(return_event, get_event)

    except Ce1susAPIException as e:
      print e
      assert False

  def test_authorized_insert_with_special_chars(self):
    event = TestInsertEvent.__generateEvent1()
    event.title = 'TitleWithSpecialChar' + u'\u2019'
    event.uuid = None
    return_event = self.api.insert_event(event, True)
    uuid = return_event.uuid
    return_event.uuid = None
    assert compare_objects(return_event, event)
    return_event.uuid = uuid
    get_event = self.api.get_event_by_uuid(uuid, withDefinition=True)
    assert (compare_objects(return_event, get_event))

  def test_unauthorized_insert(self):
    api = Ce1susAPI(TestInsertEvent.URL, 'SomeKey')
    try:
      event = TestInsertEvent.__generateEvent1()
      api.insert_event(event)
      assert False
    except Ce1susForbiddenException:
      assert True
    except Ce1susAPIException as e:
      print e
      assert False

  def test_authorized_insert_with_file(self):
    try:
      event = TestInsertEvent.__generateEvent1()
      attribute = RestAttribute()
      attribute.definition = RestAttributeDefinition()
      attribute.definition.chksum = '03c710c3265fe4488f559ebda358beb63525bda3'
      attribute.definition.name = 'description'
      attribute.definition.description = 'The raw file data'
      attribute.definition.regex = '^.+$'
      attribute.definition.class_index = 1
      attribute.definition.share = 0
      attribute.definition.relation = 0
      attribute.definition.handler_uuid = 'e8b47b60-8deb-11e3-baa8-0800200c9a66'

      attribute.value = ('TestFile.txt', 'IAphc2RhZmFzZmQ=')
      attribute.ioc = 0
      attribute.author = 'Default_Group'
      event.objects[1].attributes.append(attribute)
      return_event = self.api.insert_event(event, True)
      # TODO: find a way to test this properly
      assert return_event

    except Ce1susAPIException as e:
      print e
      assert False
