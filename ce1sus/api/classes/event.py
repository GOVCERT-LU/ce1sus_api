# -*- coding: utf-8 -*-

"""
(Description)

Created on Oct 16, 2014
"""
from ce1sus.api.classes.base import ExtendedLogingInformations
from ce1sus.api.classes.common import Properties, Status, Risk, Analysis, TLP
from ce1sus.api.classes.group import EventPermissions, Group
from ce1sus.api.classes.observables import Observable
from ce1sus.api.classes.report import Report
from ce1sus.helpers.common import strings


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class EventGroupPermission(ExtendedLogingInformations):

  def __init__(self):
    ExtendedLogingInformations.__init__(self)
    self.group = None
    self.permissions = EventPermissions('0')

  def to_dict(self, complete=True, inflated=False):
    return {'identifier': self.convert_value(self.identifier),
            'permissions': self.permissions.to_dict(),
            'group': self.group.to_dict(False, False)}

  def populate(self, json):
    self.identifier = json.get('identifier', None)
    self.permissions = EventPermissions('0')
    self.permissions.populate(json.get('permissions', None))
    self.group = Group()
    self.group.populate(json.get('group', None))


class Event(ExtendedLogingInformations):

  def __init__(self):
    ExtendedLogingInformations.__init__(self)
    self.title = None
    self.description = None
    self.last_publish_date = None
    self.published = None
    self.modified_on = None
    self.first_seen = None
    self.last_seen = None
    self.observables = list()
    self.observables_count = None
    self.comments = list()
    self.groups = list()
    self.properties = Properties('0')
    self.reports = list()
    self.originating_group = None
    self.indicators = list()

  @property
  def status(self):
    """
    returns the status

    :returns: String
    """
    return Status.get_by_id(self.status_id)

  @status.setter
  def status(self, status_text):
    """
    returns the status

    :returns: String
    """
    self.status_id = Status.get_by_value(status_text)

  @property
  def risk(self):
    """
    returns the status

    :returns: String
    """
    return Risk.get_by_id(self.risk_id)

  @risk.setter
  def risk(self, risk_text):
    """
    returns the status

    :returns: String
    """
    self.risk_id = Risk.get_by_value(risk_text)

  @property
  def analysis(self):
    """
    returns the status

    :returns: String
    """
    return Analysis.get_by_id(self.analysis_id)

  @analysis.setter
  def analysis(self, text):
    """
    returns the status

    :returns: String
    """
    self.analysis_id = Analysis.get_by_value(text)

  @property
  def tlp(self):
    """
      returns the tlp level

      :returns: String
    """

    return TLP.get_by_id(self.tlp_level_id)

  @tlp.setter
  def tlp(self, text):
    """
    returns the status

    :returns: String
    """
    self.tlp_level_id = TLP.get_by_value(text)

  def to_dict(self, complete=True, inflated=False, owner=False):
    if inflated:
      observables = list()
      for observable in self.observables:
        observables.append(observable.to_dict(complete, inflated))

      observables_count = len(observables)

      reports = list()
      for report in self.reports:
        reports.append(report.to_dict(complete, inflated))

      reports_count = len(reports)

      indicators = list()
      for indicator in self.indicators:
        indicators.append(indicator.to_dict(complete, inflated))
      indicators_length = len(indicators)
    else:
      indicators = None
      indicators_length = -1
      observables = None
      # observables_count = self.observables_count_for_permissions(event_permissions)
      observables_count = -1
      reports = None
      # reports_count = self.reports_count_for_permissions(event_permissions)
      reports_count = -1
    if complete:
      comments = list()
      if owner:
        for comment in self.comments:
          comments.append(comment.to_dict())
      groups = list()
      for group in self.groups:
        groups.append(group.to_dict(complete, False))

      result = {'identifier': self.convert_value(self.identifier),
                'title': self.convert_value(self.title),
                'description': self.convert_value(self.description),
                'last_publish_date': self.convert_value(self.last_publish_date),
                'risk': self.convert_value(self.risk),
                'status': self.convert_value(self.status),
                'tlp': self.convert_value(self.tlp),
                'analysis': self.convert_value(self.analysis),
                'creator_group': self.creator_group.to_dict(False, False),
                'modifier_group': self.modifier.to_dict(False, False),
                'created_at': self.convert_value(self.created_at),
                'published': self.convert_value(self.properties.is_shareable),
                'modified_on': self.convert_value(self.modified_on),
                'originating_group': self.originating_group.to_dict(complete, False),
                # TODO: add first and last seen
                'reports': reports,
                'reports_count': reports_count,
                'first_seen': self.convert_value(self.first_seen),
                'last_seen': self.convert_value(self.last_seen),
                'observables': observables,
                'observables_count': observables_count,
                'comments': comments,
                'properties': self.properties.to_dict(),
                'indicators': indicators,
                'indicators_count': indicators_length,
                'groups': groups
                }
    else:
      result = {'identifier': self.convert_value(self.identifier),
                'title': self.convert_value(self.title),
                'creator_group': self.creator_group.to_dict(False, False),
                'modifier_group': self.modifier.to_dict(False, False),
                'created_at': self.convert_value(self.created_at),
                'published': self.convert_value(self.properties.is_shareable),
                'modified_on': self.convert_value(self.modified_on),
                'originating_group': self.originating_group.to_dict(complete, False),
                # TODO: add first and last seen
                'first_seen': self.convert_value(self.first_seen),
                'last_seen': self.convert_value(self.last_seen),
                'observables': observables,
                'observables_count': observables_count,
                'reports': reports,
                'reports_count': reports_count,
                'risk': self.convert_value(self.risk),
                'status': self.convert_value(self.status),
                'tlp': self.convert_value(self.tlp),
                'analysis': self.convert_value(self.analysis),
                'comments': None,
                'indicators': indicators,
                'indicators_count': 0,
                'properties': self.properties.to_dict()
                }
    return result

  def populate(self, json):

    self.identifier = json.get('identifier', None)

    self.title = json.get('title', None)
    self.description = json.get('description', None)
    self.risk = json.get('risk', 'Undefined').title()
    self.status = json.get('status', 'Draft').title()
    self.tlp = json.get('tlp', 'Amber').title()
    self.analysis = json.get('analysis', 'Unknown').title()
    self.properties.populate(json.get('properties', Properties('0')))
    published = json.get('published', False)
    if published:
      if published == '1' or published == 1:
        published = True
      elif published == '0' or published == 0:
        published = True
      self.properties.is_shareable = published

    observables = json.get('observables', list())
    if observables:
      for observable in observables:
        obs = Observable()
        obs.populate(observable)
        self.observables.append(obs)
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
    first_seen = json.get('first_seen', None)
    if first_seen:
      self.first_seen = strings.stringToDateTime(first_seen)
    last_seen = json.get('last_seen', None)
    if last_seen:
      self.last_seen = strings.stringToDateTime(last_seen)
    reports = json.get('reports', None)
    if reports:
      for report in reports:
        report_instacne = Report()
        report_instacne.populate(report)
        self.reports.append(report_instacne)
    comments = json.get('comments', None)
    if comments:
      for comment in comments:
        comment_instacne = Comment()
        comment_instacne.populate(comment)
        self.comments.append(comment_instacne)
    permissions = json.get('groups', None)
    if permissions:
      for permission in permissions:
        event_permission = EventGroupPermission()
        event_permission.populate(permission)


class Comment(ExtendedLogingInformations):

  def __init__(self):
    ExtendedLogingInformations.__init__(self)
    self.comment = None

  def to_dict(self, complete=True, inflated=False):
    if complete:
      result = {'identifier': self.convert_value(self.identifier),
                'comments': self.convert_value(self.comment),
                'creator_group': self.creator_group.to_dict(complete, False),
                'modifier_group': self.modifier.group.to_dict(complete, False),
                'created_at': self.convert_value(self.created_at),
                'modified_on': self.convert_value(self.modified_on),
                }
    else:
      result = {'identifier': self.convert_value(self.identifier),
                'comment': self.convert_value(self.comment),
                }
    return result

  def populate(self, json):
    self.comment = json.get('comment', None)
