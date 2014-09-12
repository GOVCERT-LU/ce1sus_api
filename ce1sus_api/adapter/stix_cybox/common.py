# -*- coding: utf-8 -*-

"""
(Description)

Created on Aug 1, 2014
"""

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class MapperException(Exception):
  pass


class CyboxMapperException(MapperException):
  pass


class CyboxMapperDepricatedException(MapperException):
  pass


class StixMapperException(MapperException):
  pass
