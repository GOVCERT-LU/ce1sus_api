# -*- coding: utf-8 -*-

"""
(Description)

Created on Jan 8, 2015
"""
from ce1sus_api.api.restclasses import RestObject

from ce1sus.api.classes.base import ExtendedLogingInformations
from ce1sus.api.classes.common import ValueException, Properties


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'

# Note: This is not yet part of STIX should be on 1.2


class ReferenceDefinition(RestObject):

  def __init__(self):
    RestObject.__init__(self)
    self.name = None
    self.description = None
    self.referencehandler_id = None
    self.share = None
    self.regex = None
    self.chksum = None

  def to_dict(self, complete=True, inflated=False):
    if complete:
      return {'identifier': self.convert_value(self.identifier),
              'name': self.convert_value(self.name),
              'description': self.convert_value(self.description),
              'referencehandler_id': self.convert_value(self.referencehandler_id),
              'share': self.convert_value(self.share),
              'regex': self.convert_value(self.regex),
              'chksum': self.convert_value(self.chksum),
              }
    else:
      return {'identifier': self.identifier,
              'name': self.name
              }

  def populate(self, json):
    self.name = json.get('name', None)
    self.description = json.get('description', None)
    self.referencehandler_id = json.get('referencehandler_id', None)
    share = json.get('share', False)
    self.share = share
    self.regex = json.get('regex', None)


class Reference(ExtendedLogingInformations):

  def __init__(self):
    ExtendedLogingInformations.__init__(self)
    self.definition_id = None
    self.definition = None
    self.value = None
    self.properties = Properties('0')

  def to_dict(self, complete=True, inflated=False):
    return {'identifier': self.convert_value(self.identifier),
            'definition_id': self.convert_value(self.definition_id),
            'definition': self.definition.to_dict(complete, inflated),
            'value': self.convert_value(self.value),
            'created_at': self.convert_value(self.created_at),
            'modified_on': self.convert_value(self.modified_on),
            'creator_group': self.creator_group.to_dict(False, False),
            'modifier_group': self.modifier.to_dict(False, False),
            'properties': self.properties.to_dict()
            }

  def populate(self, json):
    definition_id = json.get('definition_id', None)
    if not definition_id:
      definition = json.get('definition', None)
      if definition:
        definition_id = definition.get('identifier', None)
    if self.definition_id:
      if self.definition_id != definition_id:
        raise ValueException(u'Reference definitions cannot be updated')
    if definition_id:
      self.definition_id = definition_id
    self.value = json.get('value', None)
    self.properties.populate(json.get('properties', None))


class Report(ExtendedLogingInformations):

  def __init__(self):
    ExtendedLogingInformations.__init__(self)
    self.properties = Properties('0')
    self.references = list()
    self.related_reports = list()
    self.title = None
    self.description = None
    self.short_description = None

  def to_dict(self, complete=True, inflated=False):
    references = list()
    related_reports = list()
    for reference in self.references:
      references.append(reference.to_dict(complete, inflated))
    references_count = len(self.references)

    if inflated:
      for related_report in self.related_reports:
        related_reports.append(related_report.to_dict(complete, inflated))

    related_count = len(self.related_reports)

    if complete:
      return {'identifier': self.convert_value(self.identifier),
              'title': self.convert_value(self.title),
              'description': self.convert_value(self.description),
              'short_description': self.convert_value(self.short_description),
              'references': references,
              'references_count': references_count,
              'properties': self.properties.to_dict(),
              'related_reports': related_reports,
              'related_reports_count': related_count,
              'creator_group': self.creator_group.to_dict(False, False),
              'modifier_group': self.modifier.to_dict(False, False),
              }
    else:
      return {'identifier': self.identifier,
              'title': self.title
              }

  def populate(self, json):
    self.title = json.get('title', None)
    self.description = json.get('description', None)
    self.properties.populate(json.get('properties', None))
    # TODO inflated
    self.short_description = json.get('short_description', None)
