# -*- coding: utf-8 -*-

from __future__ import absolute_import
import urllib2
import re
from dateutil import parser

from ce1sus_api.api.ce1susapi import Ce1susAPI, Ce1susAPIException, Ce1susForbiddenException, Ce1susNothingFoundException, Ce1susAPIConnectionException
from ce1sus_api.api.restclasses import RestEvent, RestObject, RestObjectDefinition, RestAttribute, RestAttributeDefinition, RestGroup


__author__ = 'Georges Toth'
__email__ = 'georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


ce1sus_risk_level = ['High', 'Medium', 'Low', 'None', 'Undefined']
ce1sus_analysis_level = ['None', 'Opened', 'Stalled', 'Completed', 'Unknown']
ce1sus_status_level = ['Confirmed', 'Draft', 'Deleted', 'Expired']

ce1sus_obj_checksums = {'network_traffic': '468bc69e746c453763f1c1ed644742628ca4bb38',
                        'generic_file': '7a6272431a4546b99081d50797201ddc25a38f4c',
                        'references': 'f4c9a69f715c3c60aa2fc15795b3834d2dc51b9d',
                        'ioc_records': '4ffb865c9d6950a643fd29d7170e849b1d077b9a',
                        'reference_document': 'dee32f113d56844d27b15c236d7fb66afdbef085',
                        'email': 'a88b7dcd1a9e3e17770bbaa6d7515b31a2d7e85d',
                        'executable_file': 'f82c52727e0d45c79cd3810704314d6c08fed47a',
                        'victim_targeting': '8062ece85c5860f862db2fddc3342c6ead52f744'
                        }
ce1sus_attr_checksums_new = {'domain': '90828f4af42b665fb1a426b3a887019b0da61eb4',
                             'email_to': 'e56afb60554c27a596338fb54862bb9f17e5f77f',
                             'ipv4_addr': 'cdfd7afaf21cede78d8d09e36aae52c82ebe1f69',
                             'traffic_content_pattern': 'cc35a2e8d1fe7b658f5124797572d6041abca614',
                             'analysis_free_text': '452fba47ced447f27f20db54bfe70370447ff5c1',
                             'reference_external_identifier': '204a2682e62980f6659d3497d87e2daea4fe5218',
                             'url': '45c2e97e2782cf8d96c1143d3d03cb2ca5715ad8',
                             'ids_rules': 'd66dc46c3d6c003104e56bfb7510239416d6588f',
                             'hash_md5': '8a3975c871c6df7ab9a890b8f0fd1fb6e4e6556e',
                             'hash_sha1': 'dc4e8dd46d60912abbfc3dd61c16ef1f91414032',
                             'hash_sha256': '1350a97f87dfb644437814905cded4a86e58a480',
                             'file_name': 'beba24a09fe92b09002616e6d703b3a14306fed1',
                             'yara_rule': '98fc9e6a364ad850765c20a0eb55ad7b2df7b3ee',
                             'hostname': '304b44f1d241b7b97a2d658cddf798042d416ca8',
                             'comment': '42dac9882bc6ab5e3c3d52cf5a7019b4c84ed20f',
                             'email_subject': '2ce464780bd3f8c2215849fd883bf236003d2778',
                             'email_from': '59cf7eefc377bdc51683521b5f340c40a55c9086',
                             'size_in_bytes': '9d99d7a9a888a8bfd0075090c33e6a707625673a',
                             'raw_file': '03c710c3265fe4488f559ebda358beb63525bda3',
                             'hash_sha384': '40c1ce5808fa21c6a90d27e4b08b7b7171a23b92',
                             'hash_sha512': '6d2cf7df2da95b6f878a9be2b754de1e6d1f6224',
                             'url_path': '8839eb1c1aec5a82fe09e9b0a29ef007395ef7ad',
                             'targeted_machine': '8b9b33a9ddcef3f612f68cc573054f3abe3a9e2c',
                             'targeted_organization': '9fd1f330ca3f879b49372b8b1efdb490c33c01c1',
                             'file_content_pattern': 'ae7bb656b0f3c66a349c713c9f8f27f111916c26'
                             }


def create_event(event_header, tag, title_prefix=''):
  event = RestEvent()
  event.title = u'{0}Event {1}'.format(title_prefix, event_header.get('id', ''))
  event.description = unicode(event_header.get('info', ''))
  event.first_seen = parser.parse(event_header.get('date'))
  event.tlp = event_header.get('tlp', 'amber')
  event.risk = event_header.get('risk', 'None')
  # event.uuid = event_header.get('uuid', None)

  if event.risk not in ce1sus_risk_level:
    event.risk = 'None'

  event.analysis = event_header.get('analysis', 'None')

  if event.analysis not in ce1sus_analysis_level:
    event.analysis = 'None'

  event.objects = []
  event.comments = []
  event.published = event_header.get('published', '1')
  event.status = u'Confirmed'

  # Gather group
  creator_name = event_header.get('corg', None)
  if creator_name:
    creator = RestGroup()
    creator.name = creator_name
  else:
    creator = None

  event.group = creator

  obj = RestObject()
  obj.definition = RestObjectDefinition()
  obj.definition.chksum = ce1sus_obj_checksums['references']
  obj.attributes = []
  obj.parent = None
  obj.children = []
  obj.group = creator

  if not event_header.get('id', '') == '':
    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.chksum = ce1sus_attr_checksums_new['reference_external_identifier']
    attribute.value = u'{0}{1} Event ID {2}'.format(title_prefix, tag, event_header.get('id', ''))
    attribute.ioc = 0
    attribute.share = 0
    attribute.group = creator
    obj.attributes.append(attribute)

  if not event_header.get('uuid', '') == '':
    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.chksum = ce1sus_attr_checksums_new['reference_external_identifier']
    attribute.value = u'{0}{1} Event UUID {2}'.format(title_prefix, tag, event_header.get('uuid', ''))
    attribute.ioc = 0
    attribute.share = 0
    attribute.group = creator
    obj.attributes.append(attribute)

  if len(obj.attributes) > 0:
    event.objects.append(obj)

  return event


def create_objects(objects, creator_name=''):
  ce1sus_objects = []

  if creator_name == '':
    creator = RestGroup()
    creator.name = creator_name
  else:
    creator = None

  for a in objects:
    obj = create_object(a, creator)
    ce1sus_objects.append(obj)

  return ce1sus_objects


def create_object(object_struct, creator, object_type='ioc_records'):
  obj = RestObject()
  obj.definition = RestObjectDefinition()
  obj.definition.chksum = ce1sus_obj_checksums[object_struct.get('type')]
  obj.attributes = []
  obj.parent = None
  obj.children = []
  obj.group = creator

  for a in object_struct['attributes']:
    type_, value, ioc, share = a

    if type_ in ['malware-sample', 'other']:
      # skip for now @TODO
      continue

    attribute = RestAttribute()
    attribute.definition = RestAttributeDefinition()
    attribute.definition.chksum = ce1sus_attr_checksums_new[type_]
    attribute.value = value
    attribute.ioc = ioc
    attribute.share = share
    attribute.group = creator
    obj.attributes.append(attribute)

  if 'children' in object_struct:
    for c in object_struct['children']:
      child = create_object(c, creator)
      obj.children.append(child)

  return obj
