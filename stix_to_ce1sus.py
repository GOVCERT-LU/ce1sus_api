#!/usr/bin/env python
# -*- coding: utf-8 -*-
from ce1sus_api.adapter.stix_converter import StixConverter
from ce1sus_api.api.ce1susapi import Ce1susAPI
from ce1sus_api.helpers.config import Configuration, ConfigKeyNotFoundException, ConfigException
from optparse import OptionParser
import os
import sys

from stix.core.stix_package import STIXPackage


__author__ = 'Weber Jean-Paul'
__email__ = 'georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'




if __name__ == '__main__':

  parser = OptionParser()
  parser.add_option('-c', dest='ce1sus', type='string', default='',
                    help='ce1sus instance to use')
  parser.add_option('--xml', dest='xml_file', type='string', default='',
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

  if options.ce1sus == '' or options.xml_file == '':
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

  stix_package = STIXPackage.from_xml(options.xml_file)
  # Set namespaces
  ce1sushost = ce1sus_api_url.replace('/REST/0.2.0', '')
  ce1sushost = ce1sushost.replace('/REST/0.2.0/', '')

  stix_convcerter = StixConverter(ce1sushost)
  event = stix_convcerter.create_ce1sus_event(stix_package)

  ce1sus_api = Ce1susAPI(ce1sus_api_url, ce1sus_api_key, verify_ssl=False)
  ce1sus_api.insert_event(event, False, True)
  print 'Done'
