#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ce1sus_api.helpers.config import Configuration, ConfigKeyNotFoundException, ConfigException
import json
from optparse import OptionParser
import os
import sys

from ce1sus.adapters.misp import MispConverter
from ce1sus.api.ce1susapi import Ce1susAPI


__author__ = 'Georges Toth'
__email__ = 'georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'

if __name__ == '__main__':

  parser = OptionParser()
  parser.add_option('-m', dest='misp', type='string', default='',
                    help='MISP instance to use')
  parser.add_option('-c', dest='ce1sus', type='string', default='',
                    help='ce1sus instance to use')
  parser.add_option('-e', dest='misp_event', type='string', default='',
                    help='MISP event ID')
  parser.add_option('-v', dest='verbose', action='store_true', default=False,
                    help='verbose output')
  parser.add_option('-d', dest='dryrun', action='store_true', default=False,
                    help='dry-run, do not store anything in ce1sus')
  parser.add_option('--xml', dest='xml', action='store_true', default=False,
                    help='output raw MISP XML')
  parser.add_option('-f', dest='f', type='string', default='',
                    help='MISP XML File')

  (options, args) = parser.parse_args()

  try:
    config_file = os.path.expanduser('~/.ce1sus_adapter.conf')
    config = Configuration(config_file)
  except ConfigException:
    print 'ERROR: Unable to load config ~/.ce1sus_adapter.conf'
    print
    parser.print_help()
    sys.exit(1)

  if options.misp == '' or options.ce1sus == '' or options.misp_event == '':
    print 'ERROR: Invalid arguments'
    print
    parser.print_help()
    sys.exit(1)

  misp_section = 'misp_{0}'.format(options.misp)
  ce1sus_section = 'ce1sus_{0}'.format(options.ce1sus)

  try:
    misp_tag = config.get(misp_section, 'tag')
    misp_api_url = config.get(misp_section, 'api_url')
    misp_api_key = config.get(misp_section, 'api_key')
  except ConfigKeyNotFoundException:
    print 'ERROR: MISP config error'
    sys.exit(1)

  try:
    ce1sus_api_url = config.get(ce1sus_section, 'api_url')
    ce1sus_api_key = config.get(ce1sus_section, 'api_key')
  except ConfigKeyNotFoundException:
    print 'ERROR: ce1sus config error'
    sys.exit(1)

  ce1sus_api = Ce1susAPI(ce1sus_api_url, ce1sus_api_key, verify_ssl=False)

  ce1sus_api.login(ce1sus_api_key)
  o_defs = ce1sus_api.get_object_definitions(True)
  a_defs = ce1sus_api.get_attribute_definitions(True)
  r_defs = ce1sus_api.get_reference_definitions(True)
  ce1sus_api.logout()

  mist_adapter = MispConverter(misp_api_url, misp_api_key, o_defs, a_defs, r_defs, misp_tag)
  print mist_adapter.get_recent_events(200)
  misp_event = options.misp_event
  if misp_event == '-':
    if options.f:
      filename = options.f

      print filename
      xml_file = open(filename)
      xml_string = xml_file.read()
      xml_file.close()

      rest_event = mist_adapter.get_event_from_xml(xml_string)
    else:
      rest_event = mist_adapter.get_event_from_xml(sys.stdin.read())
  else:
    if options.xml:
      print mist_adapter.get_xml_event(misp_event)
    else:
      rest_event = mist_adapter.get_event(misp_event)

  print json.dumps(rest_event[0].to_dict(True, True), sort_keys=True, indent=4, separators=(',', ': '))

  print 'Done'
