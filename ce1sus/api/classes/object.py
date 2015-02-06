# -*- coding: utf-8 -*-

"""
(Description)

Created on Oct 16, 2014
"""
from ce1sus.api.classes.attribute import Attribute
from ce1sus.api.classes.base import ExtendedLogingInformations, RestBase
from ce1sus.api.classes.common import Properties, ValueException
from ce1sus.api.classes.definitions import ObjectDefinition
from ce1sus.api.classes.group import Group
from ce1sus.helpers.common import strings


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class RelatedObject(RestBase):

  def __init__(self):
    RestBase.__init__(self)
    self.relation = None
    self.object = None
    self.parent_id = None

  def to_dict(self, complete=True, inflated=False):
    # flatten related object
    obj = self.object.to_dict(complete, inflated)
    obj['relation'] = self.convert_value(self.relation)
    obj['parent_object_id'] = self.convert_value(self.parent_id)
    return {'identifier': self.convert_value(self.identifier),
            'object': obj,
            'relation': self.convert_value(self.relation),
            'parent_id': self.convert_value(self.parent_id)
            }


class Object(ExtendedLogingInformations):

  def __init__(self):
    ExtendedLogingInformations.__init__(self)
    self.attributes = list()
    self.properties = Properties('0')
    self.definition_id = None
    self.definition = None
    self.related_objects = list()
    self.observable_id = None
    self.modifier = None

  def to_dict(self, complete=True, inflated=False):
    attributes = list()
    for attribute in self.attributes:
      attributes.append(attribute.to_dict(complete, inflated))
    related = list()

    attributes_count = len(self.attributes)

    if inflated:
      for related_object in self.related_objects:
        related.append(related_object.to_dict(complete, inflated))
    related_count = len(self.related_objects)

    return {'identifier': self.convert_value(self.identifier),
            'definition_id': self.convert_value(self.definition_id),
            'definition': self.definition.to_dict(complete, inflated),
            'attributes': attributes,
            'attributes_count': attributes_count,
            'creator_group': self.creator_group.to_dict(False, False),
            'modifier_group': self.modifier.to_dict(False, False),
            'created_at': self.convert_value(self.created_at),
            'modified_on': self.convert_value(self.modified_on),
            'related_objects': related,
            'related_objects_count': related_count,
            'properties': self.properties.to_dict(),
            'observable_id': self.convert_value(self.observable_id)
            }

  def populate(self, json, set_identifier=False):
    if set_identifier:
      self.identifier = json.get('idenfifier', None)
    # TODO: if inflated
    definition_id = json.get('definition_id', None)
    if definition_id:
      self.definition_id = definition_id
      definition = json.get('definition', None)
      if definition:
        definitin_instance = ObjectDefinition()
        definitin_instance.populate(definition, set_identifier)
        self.definition = definitin_instance
    if self.definition_id and self.definition:
      if self.definition_id != self.definition.identifier:
        raise ValueException(u'Object definitions cannot be updated')
    if not (self.definition_id or self.definition):
      raise ValueException(u'Object definition or definition_id must be set')
    self.properties.populate(json.get('properties', Properties('0')))
    creator_group = json.get('creator_group', None)
    if creator_group:
      cg_instance = Group()
      cg_instance.populate(creator_group, set_identifier)
      self.creator_group = cg_instance
    modifier_group = json.get('modifier_group', None)
    if modifier_group:
      cg_instance = Group()
      cg_instance.populate(modifier_group, set_identifier)
      self.modifier = cg_instance
    created_at = json.get('created_at', None)
    if created_at:
      self.created_at = strings.stringToDateTime(created_at)
    modified_on = json.get('modified_on', None)
    if modified_on:
      self.modified_on = strings.stringToDateTime(modified_on)
    rel_obs = json.get('related_objects', None)
    if rel_obs:
      for rel_ob in rel_obs:
        obj_instance = RelatedObject()
        obj_instance.populate(rel_ob, set_identifier)
        self.related_observables.append(obj_instance)

    attribtues = json.get('attributes', None)
    if attribtues:
      for attribtue in attribtues:
        attribute = Attribute()
        attribute.populate(attribtue, set_identifier)
        self.attributes.append(attribute)
