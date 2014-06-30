#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Georges Toth'
__email__ = 'georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


import sys
import os
import json
from optparse import OptionParser
from ce1sus_api.api.ce1susapi import Ce1susAPI
from ce1sus_api.api.exceptions import Ce1susAPIException, Ce1susAPIConnectionException
import ce1sus_api.adapter.ce1sus as ce1sus_adapter
import ce1sus_api.adapter.misp as misp_adapter
from ce1sus_api.helpers.config import Configuration, ConfigKeyNotFoundException, ConfigException


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

  misp_event = options.misp_event
  misp_api_headers = misp_adapter.get_api_header_parameters(misp_api_key)

  # xml = ce1sus_adapter.misp.fetch_event_list(misp_api_url, misp_api_headers)

  if misp_event == '-':
    xml = misp_adapter.from_string(sys.stdin.read())
  else:
    xml_string = misp_adapter.fetch_event(misp_api_url, misp_api_headers, misp_event)

    if options.xml:
      print xml_string

    xml = misp_adapter.from_string(xml_string)

  ce1sus_api = Ce1susAPI(ce1sus_api_url, ce1sus_api_key, verify_ssl=False)
  # load and cache ce1sus definitions
  definitions_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'definitions.json')
  ce1sus_api.load_definitions(cache=True, definitions_file=definitions_file)
  definitions = ce1sus_api.definitions
  ce1sus_adapter.ce1sus_attr_checksums = {}
  for k, v in definitions.items():
    ce1sus_adapter.ce1sus_attr_checksums[k] = v['chksum']

  rest_events = misp_adapter.parse_events(xml, misp_tag, misp_api_url, misp_api_headers)

  for e in rest_events:
    dict_ = e.to_dict()

    if options.verbose:
      print json.dumps(dict_, sort_keys=True, indent=4, separators=(',', ': '))

    if not options.dryrun:
      try:
        ce1sus_api.insert_event(e)
      except Ce1susAPIConnectionException as e:
        print e
        raise
      except Ce1susAPIException as e:
        print e
        raise
    else:
      print 'DRY-RUN: made no changes to ce1sus'

  print 'Done'
