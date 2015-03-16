# -*- coding: utf-8 -*-

"""
(Description)

Created on Oct 16, 2014
"""
from ce1sus.api.classes.base import RestBase, ExtendedLogingInformations
from ce1sus.api.classes.common import ValueException, Properties
from ce1sus.api.classes.definitions import AttributeDefinition
from ce1sus.api.classes.group import Group
from ce1sus.helpers.common import strings


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class Condition(RestBase):

  def __init__(self):
    RestBase.__init__(self)
    self.value = None
    self.description = None

  def to_dict(self, complete=True, inflated=False):
    return {'identifier': self.convert_value(self.identifier),
            'value': self.convert_value(self.value),
            'description': self.convert_value(self.description),
            }

  def populate(self, json):
    self.value = json.get('value', None)
    self.description = json.get('description', None)


class Attribute(ExtendedLogingInformations):

  def __init__(self):
    ExtendedLogingInformations.__init__(self)
    self.definition_id = None
    self.definition = None
    self.is_ioc = None
    self.value = None
    self.condition = None
    self.properties = Properties('0')
    self.modifier = None
    self.object_id = None

  def to_dict(self, complete=True, inflated=False):
    return {'identifier': self.convert_value(self.identifier),
            'definition_id': self.convert_value(self.definition_id),
            'definition': self.definition.to_dict(complete, False),
            'ioc': self.is_ioc,
            'value': self.convert_value(self.value),
            'condition': self.condition.to_dict(complete, inflated),
            'created_at': self.convert_value(self.created_at),
            'modified_on': self.convert_value(self.modified_on),
            'creator_group': self.creator_group.to_dict(False, False),
            'modifier_group': self.modifier.to_dict(False, False),
            'properties': self.properties.to_dict()
            }

  def populate(self, json):
    definition_id = json.get('definition_id', None)
    if definition_id:
      self.definition_id = definition_id
      definition = json.get('definition', None)
      if definition:
        definitin_instance = AttributeDefinition()
        definitin_instance.populate(definition)
        self.definition = definitin_instance
    if self.definition_id and self.definition:
      if self.definition.identifier and self.definition_id != self.definition.identifier:
        raise ValueException(u'Attribute definitions cannot be updated')
    if not (self.definition_id or self.definition):
      raise ValueException(u'Attribute definition or definition_id must be set')
    condition_id = json.get('condition_id', None)
    if not condition_id:
      condition = json.get('condition', None)
      if condition:
        condition_id = condition.get('identifier', None)
    if condition_id:
      self.condition_id = condition_id
    self.is_ioc = json.get('ioc', 0)
    self.value = json.get('value', None)
    self.properties.populate(json.get('properties', None))
    creator_group = json.get('creator_group', None)
    if creator_group:
      cg_instance = Group()
      cg_instance.populate(creator_group)
      self.creator_group = cg_instance
    modifier_group = json.get('modifier_group', None)
    if modifier_group:
      cg_instance = Group()
      cg_instance.populate(modifier_group)
      self.modifier = cg_instance
    created_at = json.get('created_at', None)
    if created_at:
      self.created_at = strings.stringToDateTime(created_at)
    modified_on = json.get('modified_on', None)
    if modified_on:
      self.modified_on = strings.stringToDateTime(modified_on)
