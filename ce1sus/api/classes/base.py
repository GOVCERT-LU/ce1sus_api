# -*- coding: utf-8 -*-

"""
(Description)

Created on Feb 4, 2015
"""

from datetime import datetime, date
from decimal import Decimal
from uuid import UUID

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class fakefloat(float):
    def __init__(self, value):
        self._value = value

    def __repr__(self):
        return str(self._value)


class RestBase(object):

  def __init__(self):
    self.identifier = None

  @staticmethod
  def convert_value(value):
    # TODO: rethink the wrapped file foo
    """converts the value None to '' else it will be send as None-Text"""
    if value or value == 0:
      if isinstance(value, datetime):
        # return value.strftime('%m/%d/%Y %H:%M:%S %Z')
        return value.isoformat()
      if isinstance(value, date):
        # return value.strftime('%Y-%m-%d')
        return value.isoformat()
      if isinstance(value, UUID):
        return u'{0}'.format(value)
      if isinstance(value, Decimal):
        return fakefloat(value)
      return value
    else:
      return ''


class ExtendedLogingInformations(RestBase):

  def __init__(self):
    RestBase.__init__(self)
    self.originating_group = None
    self.creator_group = None
