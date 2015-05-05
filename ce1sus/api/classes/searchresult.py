# -*- coding: utf-8 -*-

"""
(Description)

Created on Feb 18, 2015
"""
from ce1sus.api.classes.attribute import Attribute
from ce1sus.api.classes.base import RestBase
from ce1sus.api.classes.event import Event
from ce1sus.api.classes.object import Object
from ce1sus.api.classes.observables import Observable
from ce1sus.api.classes.report import Report, Reference


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class SearchResult(RestBase):

  def __init__(self):
    RestBase.__init__(self)
    self.event = None
    self.object = None
    self.observable = None
    self.attribute = None
    self.report = None
    self.reference = None

  def populate(self, json):
    item = json['event']
    self.event = Event()
    self.event.populate(item)
    # Check if not a report
    if json.get('report', None) or json.get('reference', None):
      item = json.get('report', None)
      if item:
        self.report = Report()
        self.report.populate(item)
      item = json.get('reference', None)
      if item:
        self.reference = Reference()
        self.reference.populate(item)
    else:
      item = json.get('observable', None)
      if item:
        self.observable = Observable()
        self.observable.populate(item)
      item = json.get('object', None)
      if item:
        self.object = Object()
        self.object.populate(item)
      item = json.get('attribute', None)
      if item:
        self.attribute = Attribute()
        self.attribute.populate(item)
