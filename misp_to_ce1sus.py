#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ce1sus.helpers.common.config import Configuration, ConfigKeyNotFoundException, ConfigException
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
  parser.add_option('-r', dest='recent', type='int', default=20,
                    help='import the recent x events')
  parser.add_option('-f', dest='file', type='string', default='',
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

  if (options.misp == '' or options.ce1sus == '') and (options.misp_event == '' and options.file == ''):
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

  ce1sus_api.login()
  o_defs = ce1sus_api.get_object_definitions(True)
  a_defs = ce1sus_api.get_attribute_definitions(True)
  r_defs = ce1sus_api.get_reference_definitions(True)
  if_defs = ce1sus_api.get_indicator_types(True)
  con_defs = ce1sus_api.get_conditions(True)
  ce1sus_api.logout()

  misp_adapter = MispConverter(misp_api_url, misp_api_key, o_defs, a_defs, r_defs, if_defs, con_defs, misp_tag)
  misp_adapter.syslogger.log_console = True

  rest_event = None
  rest_events = None
  misp_event = options.misp_event
  if misp_event and misp_event != '-':
    try:
      misp_event_id = int(misp_event)
    except ValueError:
      raise Exception('Please specify a valid ID')
  if options.file:
    filename = options.file
    xml_file = open(filename)
    xml_string = xml_file.read()
    xml_file.close()
    rest_event = misp_adapter.get_event_from_xml(xml_string)
  elif misp_event == '-':
    rest_event = misp_adapter.get_event_from_xml(sys.stdin.read())
  elif misp_event:
    rest_event = misp_adapter.get_event(misp_event)

  elif options.recent <= 0:
    raise Exception('Please specify at least a valid number >0 for option r')
  elif options.recent > 0:
    rest_events = misp_adapter.get_recent_events(options.recent)

  ce1sus_api.login()
  try:
    if rest_events:
      for event in rest_events:

        if options.verbose:
          print json.dumps(event.to_dict(True, True), sort_keys=True, indent=4, separators=(',', ': '))

        if options.dryrun:
          print 'DRY-RUN: made no changes to ce1sus'
        else:
          ce1sus_api.insert_event(event, False, False)
          print 'Event with uuid {0} inserted'.format(event.identifier)
    elif rest_event:
      if options.verbose:
        print json.dumps(rest_event.to_dict(True, True), sort_keys=True, indent=4, separators=(',', ': '))

      if options.dryrun:
        print 'DRY-RUN: made no changes to ce1sus'
      else:
        ce1sus_api.insert_event(rest_event, False, False)
        print 'Event with uuid {0} inserted'.format(rest_event.identifier)
    else:
      raise Exception('Unexpected Error. Please contact your local administrator')

  finally:
    ce1sus_api.logout()

  print 'Done'
