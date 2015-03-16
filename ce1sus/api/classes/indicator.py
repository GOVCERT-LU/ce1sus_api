# -*- coding: utf-8 -*-

"""
(Description)

Created on Nov 11, 2014
"""
from ce1sus.api.classes.base import RestBase, ExtendedLogingInformations
from ce1sus.api.classes.common import Properties


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class IndicatorType(RestBase):
  def __init__(self):
    self.name = None
    self.description = None

  def populate(self, json):
    self.identifier = json.get('identifier', None)
    self.name = json.get('name', None)
    self.description = json.get('description', None)

  def to_dict(self, complete=False):
    if complete:
      return {'identifier': self.convert_value(self.identifier),
              'name': self.convert_value(self.name),
              'description': self.convert_value(self.description)}
    else:
      return {'identifier': self.convert_value(self.identifier),
              'name': self.convert_value(self.name)}


class Indicator(ExtendedLogingInformations):

  def __init__(self):
    self.observables = list()
    self.title = None
    self.description = None
    self.short_description = None
    self.confidence = None
    self.type_ = list()
    self.operator = 'OR'
    self.properties = Properties('0')

  def to_dict(self, complete=True, inflated=False):
    type_ = None
    if self.type_:
      type_ = list()
      for item in self.type_:
        type_.append(item.to_dict(True))

    if inflated:
      obs = list()
      for observable in self.observables:
        obs.append(observable.to_dict(complete, inflated))
      len_obs = len(obs)
      return {'identifier': self.convert_value(self.identifier),
              'title': self.convert_value(self.title),
              'description': self.convert_value(self.description),
              'short_description': self.convert_value(self.short_description),
              'confidence': self.convert_value(self.confidence),
              'type': type_,
              'operator': self.convert_value(self.operator),
              'observables': obs,
              'observables_count': len_obs,
              'created_at': self.convert_value(self.created_at),
              'modified_on': self.convert_value(self.modified_on),
              'creator_group': self.creator_group.to_dict(False, False),
              'modifier_group': self.modifier.to_dict(False, False),
              'properties': self.properties.to_dict()
              }
    else:
      return {'identifier': self.convert_value(self.identifier),
              'title': self.convert_value(self.title),
              'description': self.convert_value(self.description),
              'short_description': self.convert_value(self.short_description),
              'confidence': self.convert_value(self.confidence),
              'type': type_,
              'operator': self.convert_value(self.operator),
              'observables': None,
              'observables_count': -1,
              'created_at': self.convert_value(self.created_at),
              'modified_on': self.convert_value(self.modified_on),
              'creator_group': self.creator_group.to_dict(False, False),
              'modifier_group': self.modifier.to_dict(False, False),
              'properties': self.properties.to_dict()
              }
