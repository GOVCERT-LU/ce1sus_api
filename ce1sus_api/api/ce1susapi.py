#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Georges Toth'
__email__ = 'georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


import sys
import os
from optparse import OptionParser
from ce1sus_api.api.ce1susapi import Ce1susAPI
from ce1sus_api.adapter.stix_converter import StixConverter
from ce1sus_api.helpers.config import Configuration, ConfigKeyNotFoundException, ConfigException


if __name__ == '__main__':

  parser = OptionParser()
  parser.add_option('-c', dest='ce1sus', type='string', default='',
                    help='ce1sus instance to use')
  parser.add_option('--uuid', dest='event_uuid', type='string', default='',
                    help='event UUID')
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

  if options.ce1sus == '' or options.event_uuid == '':
    print 'ERROR: Invalid arguments'
    print
    parser.print_help()
    sys.exit(1)
  ce1sus_section = 'ce1sus_{0}'.format(options.ce1sus)

  try:
    ce1sus_api_url = config.get(ce1sus_section, 'api_url')
    ce1sus_api_key = config.get(ce1sus_section, 'api_key')
  except ConfigKeyNotFoundException:
    print 'ERROR: ce1sus config error'
    sys.exit(1)

  ce1sus_api = Ce1susAPI(ce1sus_api_url, ce1sus_api_key, verify_ssl=False)

  event = ce1sus_api.get_event_by_uuid(options.event_uuid, withDefinition=True)

  # Set namespaces
  ce1sushost = ce1sus_api_url.replace('/REST/0.2.0', '')
  ce1sushost = ce1sushost.replace('/REST/0.2.0/', '')

  stix_convcerter = StixConverter(ce1sushost)

  stix_xml = stix_convcerter.create_stix_xml(event)
  # print stix_xml
  xmlfile = open('Event-{0}.xml'.format(options.event_uuid), 'w')
  xmlfile.write(stix_xml)
  xmlfile.close()
  print 'Done'
