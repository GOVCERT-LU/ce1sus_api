# -*- coding: utf-8 -*-

"""
(Description)

Created on Nov 11, 2014
"""
from ce1sus.api.classes.base import RestBase, ExtendedLogingInformations
from ce1sus.api.classes.common import Properties
from ce1sus.api.classes.group import Group
from ce1sus.api.classes.observables import Observable
from ce1sus.helpers.common import strings


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class IndicatorType(RestBase):
  def __init__(self):
    self.type_ = None
    self.description = None

  @classmethod
  def get_dictionary(cls):
    return {0: "Malicious E-mail",
            1: "IP Watchlist",
            2: "File Hash Watchlist",
            3: "Domain Watchlist",
            4: "URL Watchlist",
            5: "Malware Artifacts",
            6: "C2",
            7: "Anonymization",
            8: "Exfiltration",
            9: "Host Characteristics",
            10: "Compromised PKI Certificate",
            11: "Login Name",
            12: "IMEI Watchlist",
            13: "IMSI Watchlist"}

  @property
  def name(self):
    return self.get_dictionary().get(self.type_, None)

  @name.setter
  def name(self, name):
    for key, value in self.get_dictionary().iteritems():
      if value == name:
        self.type_ = key
        break

  def populate(self, json):
    self.identifier = json.get('identifier', None)
    self.name = json.get('name', None)
    self.description = json.get('description', None)

  def to_dict(self, complete=True, inflated=False):
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

  def populate(self, json):
    self.identifier = json.get('identifier', None)

    self.title = json.get('title', None)
    self.description = json.get('description', None)
    self.short_description = json.get('short_description', None)
    self.confidence = json.get('confidence', None)
    modifier_group = json.get('modifier_group', None)
    if modifier_group:
      cg_instance = Group()
      cg_instance.populate(modifier_group)
      self.modifier = cg_instance
    originating_group = json.get('originating_group', None)
    if originating_group:
      cg_instance = Group()
      cg_instance.populate(originating_group)
      self.originating_group = cg_instance
    creator_group = json.get('creator_group', None)
    if creator_group:
      cg_instance = Group()
      cg_instance.populate(creator_group)
      self.creator_group = cg_instance
    created_at = json.get('created_at', None)
    if created_at:
      self.created_at = strings.stringToDateTime(created_at)
    modified_on = json.get('modified_on', None)
    if modified_on:
      self.modified_on = strings.stringToDateTime(modified_on)
    self.operator = json.get('operator', 'OR')

    self.properties.populate(json.get('properties', Properties('0')))
    observables = json.get('observables', list())
    if observables:
      for observable in observables:
        obs = Observable()
        obs.populate(observable)
        self.observables.append(obs)
