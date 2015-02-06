# -*- coding: utf-8 -*-

"""
(Description)

Created on Nov 11, 2014
"""
from ce1sus.api.classes.base import ExtendedLogingInformations, RestBase
from ce1sus.api.classes.common import Properties
from ce1sus.api.classes.group import Group
from ce1sus.api.classes.object import Object
from ce1sus.helpers.common import strings


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class ObservableComposition(RestBase):

  def __init__(self):
    RestBase.__init__(self)
    self.properties = Properties('0')
    self.operator = 'OR'
    self.observables = list()

  def to_dict(self, complete=True, inflated=False, set_identifier=False):
    observables = list()
    for observable in self.observables:
      observables.append(observable.to_dict(complete, inflated))

    observables_count = len(self.observables)

    return {'identifier': self.convert_value(self.identifier),
            'operator': self.convert_value(self.operator),
            'observables': observables,
            'observables_count': observables_count,
            'properties': self.properties.to_dict()
            }

  def populate(self, json, set_identifier=False):
    if set_identifier:
      self.identifier = json.get('identifier', None)
    self.operator = json.get('operator', 'OR')
    self.properties.populate(json.get('properties', Properties('0')))
    observables = json.get('observables', None)
    if observables:
      for observable in observables:
        obs = Observable()
        obs.populate(observable, set_identifier)
        self.observables.append(obs)


class RelatedObservable(ExtendedLogingInformations):

  def __init__(self):
    ExtendedLogingInformations.__init__(self)
    self.relation = None
    self.confidence = None
    self.parent_id = None
    self.observable = None

  def to_dict(self, complete=True, inflated=False):
    # flatten related object
    observable = self.observable.to_dict(complete, inflated)
    observable['relation'] = self.convert_value(self.relation)
    observable['confidence'] = self.convert_value(self.confidence)
    observable['parent_observable_id'] = self.convert_value(self.parent_id)
    return {'identifier': self.convert_value(self.identifier),
            'observable': observable,
            'relation': self.convert_value(self.relation),
            'confidence': self.convert_value(self.confidence),
            'parent_id': self.convert_value(self.parent_id)
            }


class Observable(ExtendedLogingInformations):

  def __init__(self):
    ExtendedLogingInformations.__init__(self)
    self.properties = Properties('0')
    self.object = None
    self.description = None
    self.observable_composition = None
    self.related_observables = list()
    self.modifier = None
    self.event_id = None

  def to_dict(self, complete=True, inflated=False):
    obj = self.object
    if obj:
      obj = obj.to_dict(complete, inflated)

    composed = self.observable_composition
    if composed:
      composed = composed.to_dict(complete, inflated)
    related = list()

    related_count = len(related)

    if complete:
      result = {'identifier': self.convert_value(self.identifier),
                'title': self.convert_value(self.title),
                'description': self.convert_value(self.description),
                'object': obj,
                'version': self.convert_value(self.version),
                'observable_composition': composed,
                'related_observables': related,
                'related_observables_count': related_count,
                'created_at': self.convert_value(self.created_at),
                'modified_on': self.convert_value(self.modified_on),
                'creator_group': self.creator_group.to_dict(False, False),
                'modifier_group': self.modifier.to_dict(False, False),
                'properties': self.properties.to_dict()
                }
    else:
      result = {'identifier': self.convert_value(self.identifier),
                'title': self.convert_value(self.title),
                'object': obj,
                'observable_composition': composed,
                'creator_group': self.creator_group.to_dict(False, False),
                'modifier_group': self.modifier.to_dict(False, False),
                'created_at': self.convert_value(self.created_at),
                'modified_on': self.convert_value(self.modified_on),
                'modifier_group': self.convert_value(self.modifier.group.to_dict(complete, inflated)),
                'properties': self.properties.to_dict()
                }

    return result

  def populate(self, json, set_identifier=False):
    if set_identifier:
      self.identifier = json.get('identifier', None)
    self.title = json.get('title', None)
    self.description = json.get('description', None)
    self.version = json.get('version', '')
    self.properties.populate(json.get('properties', Properties('0')))
    obj = self.title = json.get('object', None)
    if obj:
      obj_instance = Object()
      obj_instance.populate(obj, set_identifier)
      self.object = obj_instance
    comp = self.title = json.get('observable_composition', None)
    if comp:
      comp_instance = ObservableComposition()
      comp_instance.populate(comp, set_identifier)
      self.observable_composition = comp_instance
    rel_obs = self.title = json.get('related_observables', None)
    if rel_obs:
      for rel_ob in rel_obs:
        obj_instance = RelatedObservable()
        obj_instance.populate(rel_ob)
        self.related_observables.append(obj_instance, set_identifier)
    modifier_group = json.get('modifier_group', None)
    if modifier_group:
      cg_instance = Group()
      cg_instance.populate(modifier_group, set_identifier)
      self.modifier = cg_instance
    creator_group = json.get('creator_group', None)
    if creator_group:
      cg_instance = Group()
      cg_instance.populate(creator_group, set_identifier)
      self.creator_group = cg_instance
    created_at = json.get('created_at', None)
    if created_at:
      self.created_at = strings.stringToDateTime(created_at)
    modified_on = json.get('modified_on', None)
    if modified_on:
      self.modified_on = strings.stringToDateTime(modified_on)
    # TODO: make valid for inflated
