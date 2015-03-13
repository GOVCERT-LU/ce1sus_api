# -*- coding: utf-8 -*-

"""
(Description)

Created on Oct 16, 2014
"""
from ce1sus.api.classes.base import RestBase


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class DefinitionException(Exception):
  pass


class AttributeDefinitionException(DefinitionException):
  pass


class ObjectDefinition(RestBase):

  def __init__(self):
    RestBase.__init__(self)
    self.name = None
    self.description = None
    self.chksum = None
    self.default_share = None
    self.chksum = None
    self.attributes = list()

  def to_dict(self, complete=True, inflated=False):

    if inflated:
      attribtues = list()
      for attribute in self.attributes:
        attribtues.append(attribute.to_dict(complete, False))
    else:
      attribtues = None
    if complete:
      return {'identifier': self.convert_value(self.identifier),
              'name': self.convert_value(self.name),
              'description': self.convert_value(self.description),
              'chksum': self.convert_value(self.chksum),
              'default_share': self.convert_value(self.default_share),
              'attributes': attribtues,
              'chksum': self.convert_value(self.chksum),
              }
    else:
      return {'identifier': self.identifier,
              'name': self.name}

  def populate(self, json):
    self.identifier = json.get('identifier', None)
    self.name = json.get('name', None)
    self.description = json.get('description', None)
    self.default_share = json.get('default_share', False)
    self.chksum = json.get('chksum', None)


class AttributeDefinition(RestBase):

  def __init__(self):
    RestBase.__init__(self)
    self.name = None
    self.description = None
    self.chksum = None
    self.default_share = None
    self.chksum = None
    self.attributehandler_id = None
    self.table_id = None
    self.relation = None
    self.share = None
    self.regex = None
    self.type_id = None
    self.default_condition_id = None
    self.objects = None
    self.chksum = None

  def to_dict(self, complete=True, inflated=False):
    if inflated:
      objects = list()
      for obj in self.objects:
        objects.append(obj.to_dict(complete, False))
    else:
      objects = None
    if complete:
      return {'identifier': self.convert_value(self.identifier),
              'name': self.convert_value(self.name),
              'description': self.convert_value(self.description),
              'attributehandler_id': self.convert_value(self.attributehandler_id),
              'table_id': self.convert_value(self.table_id),
              'relation': self.convert_value(self.relation),
              'share': self.convert_value(self.share),
              'regex': self.convert_value(self.regex),
              'type_id': self.convert_value(self.value_type_id),
              'default_condition_id': self.convert_value(self.default_condition_id),
              'objects': objects,
              'chksum': self.convert_value(self.chksum),
              }
    else:
      return {'identifier': self.identifier,
              'name': self.name,
              'default_condition_id': self.convert_value(self.default_condition_id),
              }

  def populate(self, json):
    self.identifier = json.get('identifier', None)
    self.name = json.get('name', None)
    self.description = json.get('description', None)
    self.attributehandler_id = json.get('attributehandler_id', None)
    self.table_id = json.get('table_id', None)
    self.value_type_id = json.get('type_id', None)
    self.default_condition_id = json.get('default_condition_id', None)
    relation = json.get('relation', False)
    self.relation = relation
    share = json.get('share', False)
    self.share = share
    self.regex = json.get('regex', None)
    self.chksum = json.get('chksum', None)
