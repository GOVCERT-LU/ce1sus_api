# -*- coding: utf-8 -*-

"""
(Description)

Created on Mar 17, 2015
"""
import syslog


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class SysloggerExcepton(Exception):
  pass


class Syslogger(object):

  def __init__(self, config):
    if config:
      level = config.get('syslogger', 'level', 'error').lower()
    else:
      level = 'debug'
    syslog.syslog(syslog.LOG_INFO, 'Syslog enabled')
    self.level = self.__get_level_id(level)

  def __get_level_id(self, level):
    if level == 'debug':
      return 3
    elif level == 'info':
      return 2
    elif level == 'warning':
      return 1
    elif level == 'error':
      return 0
    raise SysloggerExcepton(u'Level {0} is not supported'.format(level))

  def debug(self, message):
    if self.level >= 3:
      syslog.syslog(syslog.LOG_DEBUG, message)

  def info(self, message):
    if self.level >= 2:
      syslog.syslog(syslog.LOG_INFO, message)

  def warning(self, message):
    if self.level >= 1:
      syslog.syslog(syslog.LOG_WARNING, message)

  def error(self, message):
    if self.level >= 0:
      syslog.syslog(syslog.LOG_ERR, message)



