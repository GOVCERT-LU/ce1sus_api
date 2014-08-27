# -*- coding: utf-8 -*-

"""
(Description)

Created on Aug 26, 2014
"""

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


import sys
import os
from optparse import OptionParser
from ce1sus_api.api.ce1susapi import Ce1susAPI
from ce1sus_api.helpers.config import Configuration, ConfigKeyNotFoundException, ConfigException


if __name__ == '__main__':

  parser = OptionParser()
  parser.add_option('-f', dest='ce1sus_from', type='string', default='',
                    help='source ce1sus instance to use')
  parser.add_option('-t', dest='ce1sus_to', type='string', default='',
                    help='destination ce1sus instance to use')
  parser.add_option('--uuid', dest='event_uuid', type='string', default='',
                    help='event UUID')
  parser.add_option('-s', dest='start_date', type='string', default='',
                    help='Sync date')
  parser.add_option('-v', dest='verbose', action='store_true', default=False,
                    help='verbose output')
  (options, args) = parser.parse_args()

  try:

    config_file = os.path.expanduser('~/.ce1sus_adapter.conf')
    config = Configuration(config_file)
  except ConfigException:
    print 'ERROR: Unable to load config ~/.ce1sus_adapter.conf'
    print
    parser.print_help()
    sys.exit(1)

  if  options.ce1sus_from == '' or options.ce1sus_to == '':
    print 'ERROR: Invalid arguments'
    print
    parser.print_help()
    sys.exit(1)
  ce1sus_from_section = 'ce1sus_{0}'.format(options.ce1sus_from)
  ce1sus_to_section = 'ce1sus_{0}'.format(options.ce1sus_to)

  try:
    ce1sus_from_api_url = config.get(ce1sus_from_section, 'api_url')
    ce1sus_from_api_key = config.get(ce1sus_from_section, 'api_key')
    ce1sus_to_api_url = config.get(ce1sus_to_section, 'api_url')
    ce1sus_to_api_key = config.get(ce1sus_to_section, 'api_key')
  except ConfigKeyNotFoundException:
    print 'ERROR: ce1sus config error'
    sys.exit(1)

  ce1sus_from_api = Ce1susAPI(ce1sus_from_api_url, ce1sus_from_api_key, verify_ssl=False)
  ce1sus_to_api = Ce1susAPI(ce1sus_to_api_url, ce1sus_to_api_key, verify_ssl=False)

  if options.event_uuid:
    event = ce1sus_from_api.get_event_by_uuid(options.event_uuid, withDefinition=True)
    ce1sus_to_api.insert_event(event)
  elif options.start_date:
    # TODO get recent events with limits...
    print 'Not implemented'
  else:
    print 'ERROR: Invalid arguments. Either -s or --uuid was not specified'
    print
    parser.print_help()
    sys.exit(1)

  print 'Done'
