# -*- coding: utf-8 -*-

from __future__ import absolute_import
import os
import ntpath
import posixpath
import urllib2
import xml.etree.ElementTree as et
import ce1sus_api.adapter.ce1sus
import ce1sus_api.api.restclasses


__author__ = 'Georges Toth'
__email__ = 'georges.toth@govcert.etat.lu'
__copyright__ = 'Copyright 2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


header_tags = ['id', 'org', 'date', 'risk', 'info', 'published', 'uuid', 'attribute_count',
               'analysis', 'timestamp', 'distribution', 'proposal_email_lock', 'orgc',
               'locked', 'threat_level_id', 'publish_timestamp'
               ]
attribute_tags = ['id', 'type', 'category', 'to_ids', 'uuid', 'event_id', 'distribution',
                  'timestamp', 'value', 'ShadowAttribute'
                  ]

object_map = {'Network activity': 'network_traffic',
              'Payload delivery': 'generic_file',
              }

attribute_map = {'domain': 'domain',
                 'email-subject': 'email_subject',
                 'email-src': 'email_from',
                 'email-dst': 'email_to',
                 'ip-dst': 'ipv4_addr',
                 'ip-src': 'ipv4_addr',
                 'pattern-in-traffic': 'traffic_content_pattern',
                 'text': 'analysis_free_text',
                 'url': 'url',
                 'snort': 'ids_rules',
                 'md5': 'hash_md5',
                 'sha1': 'hash_sha1',
                 'sha256': 'hash_sha256',
                 'sha384': 'hash_sha384',
                 'sha512': 'hash_sha512',
                 'filename': 'file_name',
                 'yara': 'yara_rule',
                 'hostname': 'hostname',
                 'comment': 'comment',
                 'link': 'url',
                 'http-method': 'http_method',
                 'user-agent': 'http_user_agent',
                 'pattern-in-memory': 'memory_pattern',
                 'regkey': 'win_registry_key',
                 'vulnerability': 'vulnerability_cve',
                 'as': 'analysis_free_text',
                 'pattern-in-file': 'file_content_pattern',
                 }

threat_level_id_map = {'1': 'Low',
                       '2': 'Medium',
                       '3': 'High',
                       '4': 'None',
                       }


def guess_hash_type(hash_):
  '''Supports md5, sha1, sha-256, sha-384, sha-512'''
  hash_types = {32: 'md5',
                40: 'sha1',
                64: 'sha256',
                96: 'sha384',
                128: 'sha512',
                }

  if len(hash_) in hash_types:
    return hash_types[len(hash_)]

  raise ValueError('Unable to determine hash type')


def get_api_header_parameters(api_key):
  return {'Accept': 'application/xml',
          'Authorization': api_key}


def fetch_event_list(api_url, api_headers, limit=25):
  url = api_url + '/events/index/limit:{0}.xml'.format(limit)

  req = urllib2.Request(url, None, api_headers)
  resp = urllib2.urlopen(req).read()
  xml = et.fromstring(resp)

  return xml


def fetch_event(api_url, api_headers, event_id):
  url = '{0}/events/{1}'.format(api_url, event_id)

  req = urllib2.Request(url, None, api_headers)
  resp = urllib2.urlopen(req).read()

  return resp


def fetch_attachment(api_url, api_headers, attribute_id):
  url = '{0}/attributes/download/{1}'.format(api_url, attribute_id)

  req = urllib2.Request(url, None, api_headers)
  resp = urllib2.urlopen(req).read()

  return resp


def from_string(xml_string):
  xml = et.fromstring(xml_string)

  return xml


def parse_events(xml, misp_tag, api_url, api_headers):
  events = xml.iterfind('./Event')
  rest_events = []

  for event in events:
    event_header = parse_event_header(event)
    event_attributes = parse_event_objects(event, api_url, api_headers)
    rest_event = ce1sus_api.adapter.ce1sus.create_event(event_header, misp_tag, title_prefix='MISP ')

    if len(event_attributes) > 0:
      rest_event.objects += ce1sus_api.adapter.ce1sus.create_objects(event_attributes)

    rest_events.append(rest_event)

  return rest_events


def parse_event_header(event):
  event_header = {}

  for h in header_tags:
    e = event.find(h)
    if not e is None and not e.tag in event_header:
      event_header[e.tag] = e.text

      if h == 'threat_level_id':
        event_header['risk'] = threat_level_id_map[e.text]

  return event_header


def parse_event_objects(event, api_url=None, api_headers=None):
  event_objects = []
  ioc_object = {'type': 'ioc_records', 'attributes': []}
  ref_object = {'type': 'references', 'attributes': [], 'children': []}

  for attrib in event.iter(tag='Attribute'):
    type_ = ''
    value = ''
    category = ''
    id_ = ''
    data = None
    ioc = 0
    share = 1
    distribution = 0

    for a in attribute_tags:
      e = attrib.find(a)
      if not e is None:
        if e.tag == 'type':
          type_ = e.text.lower()
        elif e.tag == 'value':
          value = e.text
        elif e.tag == 'to_ids':
          ioc = int(e.text)
        elif e.tag == 'category':
          category = e.text.lower()
        elif e.tag == 'data':
          data = e.text
        elif e.tag == 'id':
          id_ = e.text
        elif e.tag == 'distribution':
          distribution = int(e.text)

    if type_ in ('filename|md5', 'filename|sha1', 'filename|sha256'):
      hash_type = type_.split('|')[1]
      type_ = attribute_map[hash_type]
      filename, hash_value = value.split('|')
      gf_object = {'type': 'generic_file', 'attributes': []}

      gf_object['attributes'].append(('file_name', filename, ioc, share))
      gf_object['attributes'].append((type_, hash_value, ioc, share))
      event_objects.append(gf_object)
    elif type_ in ('malware-sample', 'email-attachment') or (category in ('antivirus detection') and type_ in ('attachment')):
      hash_type = None
      gf_object = {'type': 'generic_file', 'attributes': []}

      if '|' in value:
        filename, hash_value = value.split('|')

        try:
          hash_type = guess_hash_type(hash_value)
        except ValueError as e:
          print u'Error determining hash type for hash value "{0}", ignoring'.format(hash_value)
      else:
        filename = value

      if not hash_type is None:
        type_ = attribute_map[hash_type]
        gf_object['attributes'].append((type_, hash_value, ioc, share))

      if '\\' in filename:
        # naive way of detecting windows path
        gf_object['attributes'].append(('file_full_path', filename, ioc, share))
        filename = ntpath.basename(filename)
      elif '/' in filename:
        # naive way of detecting unix path
        gf_object['attributes'].append(('file_full_path', filename, ioc, share))
        filename = posixpath.basename(filename)

      gf_object['attributes'].append(('file_name', filename, ioc, share))

      try:
        data = fetch_attachment(api_url, api_headers, id_)
      except urllib2.HTTPError:
        data = None
        print u'Failed to download file "{0}" id:{1}, add manually'.format(filename, id_)

      if not data is None:
        ce1sus_file = ce1sus_api.api.restclasses.Ce1susWrappedFile(str_=data, name=filename)
        gf_object['attributes'].append(('raw_file', ce1sus_file, 0, share))

      event_objects.append(gf_object)
    elif category == 'external analysis' and type_ == 'attachment':
      if not (api_url is None and api_headers is None):
        try:
          data = fetch_attachment(api_url, api_headers, id_)
        except urllib2.HTTPError:
          print 'Failed to download file "{0}" id:{1}'.format(value, id_)
          continue
          raise

        ce1sus_file = ce1sus_api.api.restclasses.Ce1susWrappedFile(str_=data, name=value)

        ref_doc_object = {'type': 'reference_document', 'attributes': []}
        ref_doc_object['attributes'].append(('raw_document_file', ce1sus_file, 0, share))
        ref_object['children'].append(ref_doc_object)
      else:
        raise Exception('Cannot download files in offline mode!')
    elif category == 'internal reference':
      if type_ == 'text':
        ref_object['attributes'].append(('reference_internal_case', value, ioc, share))
      elif type_ in attribute_map:
        ref_object['attributes'].append((attribute_map[type_], value, ioc, share))
      elif type_ in ce1sus_api.adapter.ce1sus.ce1sus_attr_checksums:
        # last resort, check if type exists in ce1sus
        ref_object['attributes'].append((type_, value, ioc, share))
      else:
        raise Exception('Invalid type')
    else:
      overriden_type = False

      if type_ == 'snort':
        value = u'snort:{0}'.format(value)
      elif type_ == 'url' and not '://' in value:
        type_ = 'url_path'
        overriden_type = True
      elif type_ == 'other':
        type_ = 'text'
      elif not type_ in attribute_map and not type_ in ce1sus_api.adapter.ce1sus.ce1sus_attr_checksums and ' ' in type_:
        tmp_type = type_.replace(' ', '_')

        if tmp_type in attribute_map or tmp_type in ce1sus_api.adapter.ce1sus.ce1sus_attr_checksums:
          type_ = tmp_type
          overriden_type = True

      if not overriden_type:
        if type_ in attribute_map:
          type_ = attribute_map[type_]
        elif type_ in ce1sus_api.adapter.ce1sus.ce1sus_attr_checksums:
          # last resort, check if type exists in ce1sus
          ref_object['attributes'].append((type_, value, ioc, share))
        else:
          # debug output
          print u'Category: "{0}"'.format(category)
          print u'Type: "{0}"'.format(type_)
          print u'Value: "{0}"'.format(value)

          raise Exception('Invalid type')

      ioc_object['attributes'].append((type_, value, ioc, share))

  if len(ioc_object['attributes']) > 0:
    event_objects.append(ioc_object)
  if len(ref_object['attributes']) > 0 or len(ref_object['children']) > 0:
    event_objects.append(ref_object)

  return event_objects
