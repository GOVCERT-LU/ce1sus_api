# -*- coding: utf-8 -*-

"""
(Description)

Created on Feb 20, 2015
"""
from StringIO import StringIO
from ce1sus_api.helpers.datumzait import DatumZait
from copy import deepcopy
from dateutil import parser
from os import makedirs, remove
from os.path import isdir, isfile
import re
import urllib2
from uuid import uuid4
from zipfile import ZipFile

from ce1sus.api.classes.attribute import Attribute
from ce1sus.api.classes.event import Event
from ce1sus.api.classes.group import Group
from ce1sus.api.classes.indicator import Indicator
from ce1sus.api.classes.object import Object
from ce1sus.api.classes.observables import Observable, ObservableComposition
from ce1sus.api.classes.report import Report, Reference
from ce1sus.helpers.common.syslogger import Syslogger
import xml.etree.ElementTree as et


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


def remove_non_ioc(observable):
  if observable.object:
    iocs = list()
    for attribute in observable.object.attributes:
      if attribute.is_ioc:
        iocs.append(attribute)
    if iocs:
      observable.object.attributes = iocs
    else:
      return None
  elif observable.observable_composition:
    result = list()
    for obs in observable.observable_composition.observables:
      ret = remove_non_ioc(obs)
      if ret:
        result.append(ret)
    if result:
      observable.observable_composition.observables = result
    else:
      return None

  if observable.related_observables:
    result = list()
    for related_observable in observable.related_observables:
      ret = remove_non_ioc(related_observable)
      if ret:
        result.append(ret)
    if result:
      observable.related_observables = result
    else:
      return None
  return observable


def clone_observable(observable):
  newobj = deepcopy(observable)
  # remove non ioc objects
  newobj = remove_non_ioc(newobj)
  return newobj


class MispConverterException(Exception):
  pass


class MispMappingException(MispConverterException):
  pass


class MispConverter(object):

  ce1sus_risk_level = ['High', 'Medium', 'Low', 'None', 'Undefined']
  ce1sus_analysis_level = ['None', 'Opened', 'Stalled', 'Completed', 'Unknown']
  ce1sus_status_level = ['Confirmed', 'Draft', 'Deleted', 'Expired']

  header_tags = ['id', 'org', 'date', 'risk', 'info', 'published', 'uuid', 'attribute_count',
                 'analysis', 'timestamp', 'distribution', 'proposal_email_lock', 'orgc',
                 'locked', 'threat_level_id', 'publish_timestamp'
                 ]

  threat_level_id_map = {'1': 'High',
                         '2': 'Medium',
                         '3': 'Low',
                         '4': 'None',
                         }

  analysis_id_map = {'0': 'Opened',
                     '1': 'Opened',
                     '2': 'Completed',
                     }

  distribution_to_tlp_map = {'0': 'red',
                             '1': 'amber',
                             '2': 'amber',
                             '3': 'green'
                             }

  attribute_tags = ['id', 'type', 'category', 'to_ids', 'uuid', 'event_id', 'distribution', 'timestamp', 'value', 'ShadowAttribute', 'uuid', 'comment']

  def get_api_header_parameters(self):
    return {'Accept': 'application/xml',
            'Authorization': self.api_key}

  def __init__(self, api_url, api_key, ce1sus_attribute_definitions, ce1sus_object_definitions, reference_definitions, indicator_types, conditions, misp_tag='Generic MISP'):
    self.api_url = api_url
    self.api_key = api_key
    self.api_headers = self.get_api_header_parameters()
    self.tag = misp_tag
    self.object_definitions = ce1sus_attribute_definitions
    self.attribute_definitions = ce1sus_object_definitions
    self.reference_definitions = reference_definitions
    self.indicator_types = indicator_types
    self.conditions = conditions
    self.dump = False
    self.file_location = None
    self.syslogger = Syslogger()
    self.dump = False
    self.file_location = '/tmp'

  def set_event_header(self, event, rest_event, title_prefix=''):
    event_header = {}
    for h in MispConverter.header_tags:
      e = event.find(h)
      if e is not None and e.tag not in event_header:
        event_header[e.tag] = e.text

        if h == 'threat_level_id':
          event_header['risk'] = MispConverter.threat_level_id_map[e.text]
        elif h == 'analysis':
          event_header['analysis'] = MispConverter.analysis_id_map[e.text]

    if not event_header.get('description', '') == '':
      # it seems to be common practice to specify TLP level in the event description
      m = re.search(r'tlp[\s:\-_]{0,}(red|amber|green|white)', event_header['description'], re.I)
      if m:
        event_header['tlp'] = m.group(1).lower()
    else:
      try:
        event_header['tlp'] = MispConverter.distribution_to_tlp_map[event_header['distribution']]
      except KeyError:
        event_header['tlp'] = 'amber'

    # Populate the event
    event_id = event_header.get('id', '')
    rest_event.identifier = event_header.get('uuid', None)
    if not rest_event.identifier:
      message = 'Cannot find uuid for event {0} generating one'.format(event_id)
      self.syslogger.warning(message)
      # raise MispMappingException(message)
      rest_event.identifier = u'{0}'.format(uuid4())
    rest_event.title = u'{0}Event {1}'.format(title_prefix, event_id)
    rest_event.description = unicode(event_header.get('info', ''))
    date = event_header.get('date', None)
    if date:
      rest_event.first_seen = parser.parse(date)
    else:
      rest_event.first_seen = DatumZait.utcnow()
    rest_event.tlp = event_header.get('tlp', 'amber')
    rest_event.risk = event_header.get('risk', 'None')
    # event.uuid = event_header.get('uuid', None)

    if rest_event.risk not in MispConverter.ce1sus_risk_level:
      rest_event.risk = 'None'

    rest_event.analysis = event_header.get('analysis', 'None')

    if rest_event.analysis not in MispConverter.ce1sus_analysis_level:
      rest_event.analysis = 'None'

    rest_event.objects = []
    rest_event.comments = []

    published = event_header.get('published', '1')
    if published == '1':
      rest_event.properties.is_shareable = True
    else:
      rest_event.properties.is_shareable = False
    rest_event.status = u'Confirmed'
    rest_event.originating_group = Group()
    rest_event.originating_group.name = event_header.get('corg', None)
    rest_event.creator_group = Group()
    rest_event.creator_group.name = event_header.get('org', None)
    rest_event.modifier = rest_event.creator_group
    return event_id

  def append_attributes(self, obj, observable, id_, category, type_, value, ioc, share, event, uuid):
    if '|' in type_:
      # it is a composed attribute
      if type_ in ('filename|md5', 'filename|sha1', 'filename|sha256'):
        splitted = type_.split('|')
        if len(splitted) == 2:
          first_type = splitted[0]
          second_type = splitted[1]
          splitted_values = value.split('|')
          first_value = splitted_values[0]
          second_value = splitted_values[1]
          self.append_attributes(obj, observable, id_, category, first_type, first_value, ioc, share, event, uuid)
          self.append_attributes(obj, observable, id_, category, second_type, second_value, ioc, share, event, uuid4())
        else:
          message = 'Composed attribute {0} splits into more than 2 elements'.format(type_)
          self.syslogger.error(message)
          raise MispMappingException(message)
      else:
        message = 'Composed attribute {0} cannot be mapped'.format(type_)
        self.syslogger.error(message)
        raise MispMappingException(message)
      pass
    elif type_ == 'regkey':
      value = value.replace('/', '\\')
      pos = value.find("\\")
      key = value[pos + 1:]
      hive = value[0:pos]
      if hive == 'HKLM' or 'HKEY_LOCAL_MACHINE' in hive:
        hive = 'HKEY_LOCAL_MACHINE'
      elif hive == 'HKCU' or 'HKEY_CURRENT_USER' in hive or hive == 'HCKU':
        hive = 'HKEY_CURRENT_USER'
      elif hive == 'HKEY_CURRENTUSER':
        hive = 'HKEY_CURRENT_USER'
      elif hive in ['HKCR', 'HKEY_CLASSES_ROOT']:
        hive = 'HKEY_CLASSES_ROOT'
      else:
        if hive[0:1] == 'H' and hive != 'HKCU_Classes':
          message = '"{0}" not defined'.format(hive)
          self.syslogger.error(message)
          raise MispMappingException(message)
        else:
          hive = None

      if hive:
        self.append_attributes(obj, observable, id_, category, 'WindowsRegistryKey_Hive', hive, ioc, share, event, uuid4())
      self.append_attributes(obj, observable, id_, category, 'WindowsRegistryKey_Key', key, ioc, share, event, uuid)

    elif category in ['external analysis', 'artifacts dropped', 'payload delivery'] and type_ == 'malware-sample':
      filename = value
      filename_uuid = uuid
      splitted = value.split('|')
      if len(splitted) == 2:
        first_type = 'file_name'

        first_value = splitted[0]
        filename = first_value
        second_value = splitted[1]
        second_type = self.get_hash_type(second_value)
        self.append_attributes(obj, observable, id_, category, first_type, first_value, ioc, share, event, uuid)
        self.append_attributes(obj, observable, id_, category, second_type, second_value, ioc, share, event, uuid4())
      else:
        message = 'Composed attribute {0} splits into more than 2 elements'.format(type_)
        self.syslogger.error(message)
        raise MispMappingException(message)

      # Download the attachment if it exists
      data = self.fetch_attachment(id_, filename_uuid, event.identifier, filename)
      if data:

        message = u'Downloaded file "{0}" id:{1}'.format(filename, id_)
        self.syslogger.info(message)
        print message
        # build raw_artifact
        raw_artifact = Object()
        raw_artifact.identifier = uuid4()
        self.set_properties(raw_artifact, share)
        self.set_extended_logging(raw_artifact, event)
        raw_artifact.definition = self.get_object_definition('Artifact', None, None)
        if raw_artifact.definition:
          raw_artifact.definition_id = raw_artifact.definition.identifier
        else:
          message = 'Could not find object definition Artifact'
          self.syslogger.error(message)
          raise MispMappingException(message)

        # add raw artifact
        attr = Attribute()
        attr.identifier = uuid4()
        attr.definition = self.get_attibute_definition('', 'raw_artifact', None, raw_artifact, observable, attr)
        if attr.definition:
          attr.definition_id = attr.definition.identifier
        else:
          message = 'Could not find attribute definition raw_artifact'
          self.syslogger.error(message)
          raise MispMappingException(message)
        attr.value = data
        obj.related_objects.append(raw_artifact)
      else:
        message = u'Failed to download file "{0}" id:{1}, add manually'.format(filename, id_)
        print message
        self.syslogger.warning(message)

    else:
      attribute = Attribute()
      attribute.identifier = uuid
      self.set_properties(attribute, share)
      self.set_extended_logging(attribute, event)
      attribute.definition = self.get_attibute_definition(category, type_, value, obj, observable, attribute)
      if attribute.definition:
        attribute.definition_id = attribute.definition.identifier
        attribute.value = value
        if ioc == 1:
          attribute.is_ioc = True
        else:
          attribute.is_ioc = False
        attribute.properties.is_shareable = True

        obj.attributes.append(attribute)

  def get_hash_type(self, value):
    '''Supports md5, sha1, sha-256, sha-384, sha-512'''
    hash_types = {32: 'hash_md5',
                  40: 'hash_sha1',
                  64: 'hash_sha256',
                  96: 'hash_sha384',
                  128: 'hash_sha512',
                  }
    if len(value) in hash_types:
      return hash_types[len(value)]
    else:
      message = 'Cannot map hash {0}'.format(value)
      self.syslogger.error(message)
      raise MispMappingException(message)

  def get_object_definition(self, category, type_, value):
    # compose the correct chksum/name
    chksum = None
    name = None
    if category == 'Artifact':
      name = category
    elif type_ in ['filename|md5', 'filename|sha1', 'filename|sha256', 'md5', 'sha1', 'sha256'] or category in ['antivirus detection']:
      name = 'file'
    elif type_ in ['domain']:
      name = 'DomainName'
    elif type_ in ['email-src', 'email-attachment', 'email-subject', 'email-dst']:
      name = 'email'
    elif category in ['network activity', 'payload delivery']:
      if type_ in ['ip-dst', 'ip-src']:
        name = 'Address'
      elif type_ in ['url']:
        name = 'URI'
      elif type_ in ['hostname']:
        name = 'Hostname'
      elif type_ in ['http-method', 'user-agent']:
        name = 'HTTPSession'
      elif type_ in ['vulnerability', 'malware-sample', 'filename']:
        name = 'file'
      elif type_ in ['text', 'as', 'comment', 'pattern-in-traffic']:

        message = u'Category {0} Type {1} with value {2} not mapped map manually'.format(category, type_, value)
        print message
        self.syslogger.warning(message)
        return None
      elif 'snort' in type_:
        name = 'IDSRule'
    elif category in ['payload type', 'payload installation']:
      name = 'file'
    elif category in ['artifacts dropped']:
      if 'yara' in type_ or 'snort' in type_:
        name = 'IDSRule'
      elif type_ == 'mutex':
        name = 'Mutex'
      elif 'pipe' in type_:
        name = 'Pipe'
      elif type_ == 'text':
        message = u'Category {0} Type {1} with value {2} not mapped map manually'.format(category, type_, value)
        print message
        self.syslogger.warning(message)
        return None
      else:
        name = 'Artifact'
    elif category in ['external analysis']:
      if type_ == 'malware-sample':
        name = 'file'
    elif category in ['persistence mechanism']:
      if type_ == 'regkey':
        name = 'WindowsRegistryKey'
      else:
        raise MispMappingException('Type {0} not defined'.format(type_))
    elif category in ['targeting data']:
      message = u'Category {0} Type {1} with value {2} not mapped map manually'.format(category, type_, value)
      print message
      self.syslogger.warning(message)
      return None
    if name or chksum:
      # search for it
      for object_definition in self.object_definitions:
        if object_definition.chksum == chksum or object_definition.name == name:
          return object_definition

    # if here no def was found raise exception
    message = u'No object definition for {0}/{1} and value "{2}" can be found'.format(category, type_, value)
    print message
    self.syslogger.error(message)
    raise MispMappingException(message)

  def get_reference_definition(self, category, type_, value):
    # compose the correct chksum/name
    chksum = None
    name = None
    if type_ == 'url':
      name = 'link'
    elif type_ == 'text':
      name = 'comment'
    else:
      name = type_

    if name or chksum:
      # search for it
      for reference_definition in self.reference_definitions:
        if reference_definition.name == name:
          return reference_definition

    # if here no def was found raise exception
    message = u'No reference definition for {0}/{1} and value "{2}" can be found'.format(category, type_, value)
    print message
    self.syslogger.error(message)
    raise MispMappingException(message)

  def get_condition(self, condition):
    for cond in self.conditions:
      if cond.value == condition:
        return cond
    raise MispMappingException(u'Condition {0} is not defined'.format(condition))

  def get_attibute_definition(self, category, type_, value, obj, observable, attribute):
    # compose the correct chksum/name
    chksum = None
    name = None

    if type_ == 'raw_artifact':
      name = type_

    if 'pattern' in type_:
      attribute.condition = self.get_condition('Like')
    else:
      attribute.condition = self.get_condition('Equals')

    if category == 'antivirus detection' and type_ == 'text':
      name = 'comment'

    elif type_ == 'pattern-in-file':
      name = 'pattern-in-file'
    elif type_ == 'pattern-in-memory':
      name = 'pattern-in-memory'
    elif type_ in ['md5', 'sha1', 'sha256']:
      name = u'hash_{0}'.format(type_)
    elif type_ in ['filename']:
      name = 'file_name'
    elif type_ == 'filename' and ('\\' in value or '/' in value):
      name = 'file_path'
    elif type_ == 'domain':
      name = 'DomainName_Value'
    elif type_ == 'email-src' or type_ == 'email-dst':
      name = 'email_sender'
    elif type_ == 'email-attachment':
      name = 'email_attachment_file_name'
    elif 'yara' in type_:
      name = 'yara_rule'
    elif 'snort' in type_:
      name = 'snort_rule'
    elif category in ['network activity', 'payload delivery']:
      if type_ in ['ip-dst']:
        name = 'ipv4_addr'
        observable.description = observable.description + ' - ' + 'Destination IP'
      elif type_ in ['ip-src']:
        name = 'ipv4_addr'
        observable.description = observable.description + ' - ' + 'Source IP'
      elif type_ in ['hostname']:
        name = 'Hostname_Value'
      elif type_ in ['url']:
        name = 'url'
        if type_ == 'url' and '://' not in value:
          attribute.condition = 'Like'
      elif type_ == 'http-method':
        name = 'HTTP_Method'
      elif type_ in ['vulnerability']:
        name = 'vulnerability_cve'
      elif type_ in ['user-agent']:
        name = 'User_Agent'
      # Add to the observable the comment destination as in this case only one address will be present in the observable

    # try auto assign
    elif type_ == 'mutex':
      name = 'Mutex_name'
    elif 'pipe' in type_:
      name = 'Pipe_Name'
    elif category == 'artifacts dropped':
      if type_ in ['text']:
        print u'Category {0} Type {1} with value {2} not mapped map manually'.format(category, type_, value)
        return None
    elif category == 'payload installation':
      if type_ == 'attachment':
        name = 'file_name'
    if not name:
      name = type_.replace('-', '_').replace(' ', '_')

    definition = self.__find_attr_def(name, chksum)

    if definition:
      return definition
    else:
      name = name.title()
      definition = self.__find_attr_def(name, chksum)
      if definition:
        return definition
    # if here no def was found raise exception

    message = u'No attribute definition for {0}/{1} and value {2} can be found {3}'.format(category, type_, value, name)
    print message
    self.syslogger.error(message)
    raise MispMappingException(message)

  def __find_attr_def(self, name, chksum):
    if name or chksum:
      # search for it
      for attribute_definition in self.attribute_definitions:
        if attribute_definition.chksum == chksum or attribute_definition.name == name:
          return attribute_definition
    return None

  def create_reference(self, uuid, category, type_, value, data, comment, ioc, share, event):
    reference = Reference()
    # TODO map reference
    reference.identifier = uuid
    reference.definition = self.get_reference_definition(category, type_, value)
    reference.definition_id = reference.definition.identifier
    reference.value = value
    self.set_extended_logging(reference, event)
    return reference

  def create_observable(self, id_, uuid, category, type_, value, data, comment, ioc, share, event):
    if (category in ['external analysis', 'internal reference', 'targeting data', 'antivirus detection'] and type_ in ['attachment', 'comment', 'link', 'text', 'url', 'text']) or (category == 'internal reference' and type_ in ['text', 'comment']) or type_ == 'other' or (category == 'attribution' and type_ == 'comment') or category == 'other' or (category == 'antivirus detection' and type_ == 'link'):
      # make a report
      # Create Report it will be just a single one
      reference = self.create_reference(uuid, category, type_, value, data, comment, ioc, share, event)
      if len(event.reports) == 0:
        report = Report()
        report.identifier = uuid4()
        self.set_extended_logging(report, event)
        if comment:
          if report.description:
            report.description = report.description + ' - ' + comment
          else:
            report.description = comment
        event.reports.append(report)
      event.reports[0].references.append(reference)
    elif category == 'attribution':
      reference = self.create_reference(uuid, category, type_, value, data, comment, ioc, share, event)
      reference.value = u'Attribution: '.format(reference.value)
      if len(event.reports) == 0:
        report = Report()
        report.identifier = uuid4()
        self.set_extended_logging(report, event)
        if comment:
          if report.description:
            report.description = report.description + ' - ' + comment
          else:
            report.description = comment
        event.reports.append(report)

    else:
      observable = self.make_observable(event, comment, share)
      # create object
      obj = Object()
      obj.identifier = uuid4()
      self.set_properties(obj, share)
      self.set_extended_logging(obj, event)
      observable.object = obj
      obj.definition = self.get_object_definition(category, type_, value)
      if obj.definition:
        obj.definition_id = obj.definition.identifier

        # create attribute(s) for object
        self.append_attributes(obj, observable, id_, category, type_, value, ioc, share, event, uuid)
        if not observable.description:
          observable.description = None
        return observable
      else:
        return None

  def set_properties(self, instance, shared):
    instance.properties.is_proposal = False
    instance.properties.is_rest_instert = True
    instance.properties.is_validated = False
    instance.properties.is_shareable = shared

  def make_observable(self, event, comment, shared):
    result_observable = Observable()
    result_observable.identifier = uuid4()
    # The creator of the result_observable is the creator of the object
    self.set_extended_logging(result_observable, event)

    result_observable.event_id = event.identifier

    if comment is None:
      result_observable.description = ''
    else:
      result_observable.description = comment

    self.set_properties(result_observable, shared)

    result_observable.created_at = DatumZait.utcnow()
    result_observable.modified_on = DatumZait.utcnow()

    return result_observable

  def map_observable_composition(self, array, event, title, shared):
    result_observable = self.make_observable(event, None, True)
    if title:
      result_observable.title = 'Indicators for "{0}"'.format(title)
    composed_attribute = ObservableComposition()
    composed_attribute.identifier = uuid4()
    self.set_properties(composed_attribute, shared)
    result_observable.observable_composition = composed_attribute

    for observable in array:
      composed_attribute.observables.append(observable)

    return result_observable

  def parse_attributes(self, event, misp_event):

    # make lists
    mal_email = list()
    ips = list()
    file_hashes = list()
    domains = list()
    urls = list()
    artifacts = list()
    c2s = list()
    others = list()
    attrs = misp_event.iter(tag='Attribute')
    for attrib in attrs:
      type_ = ''
      value = ''
      category = ''
      id_ = ''
      data = None
      ioc = 0
      share = 1
      comment = ''
      uuid = None

      for a in MispConverter.attribute_tags:
        e = attrib.find(a)
        if e is not None:
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
          elif e.tag == 'comment':
            comment = e.text
          elif e.tag == 'uuid':
            uuid = e.text
      # ignore empty values:
      if value:
        observable = self.create_observable(id_, uuid, category, type_, value, data, comment, ioc, share, event)
        # returns all attributes for all context (i.e. report and normal properties)
        if observable and isinstance(observable, Observable):
          obj = observable.object
          attr_def_name = None
          if obj:
            if len(obj.attributes) == 1:
              attr_def_name = obj.attributes[0].definition.name
            elif len(obj.attributes) == 2:
              for attr in obj.attributes:
                if 'hash' in attr.definition.name:
                  attr_def_name = attr.definition.name
                  break
            else:
              message = u'Misp Attribute {0} defined as {1}/{2} with value {3} resulted too many attribtues'.format(id_, category, type_, value)
              self.syslogger.error(message)
              raise MispMappingException(message)
          else:
            message = u'Misp Attribute {0} defined as {1}/{2} with value {3} resulted in an empty observable'.format(id_, category, type_, value)
            self.syslogger.error(message)
            raise MispMappingException(message)

          # TODO make sorting via definitions
          if attr_def_name:
            if 'raw' in attr_def_name:
              artifacts.append(observable)
            elif 'c&c' in attr_def_name:
              c2s.append(observable)
            elif 'ipv' in attr_def_name:
              ips.append(observable)
            elif 'hash' in attr_def_name:
              file_hashes.append(observable)
            elif 'email' in attr_def_name:
              mal_email.append(observable)
            elif 'domain' in attr_def_name or 'hostname' in attr_def_name:
              domains.append(observable)
            elif 'url' in attr_def_name:
              urls.append(observable)
            else:
              others.append(observable)
          else:
            others.append(observable)
      else:
        self.syslogger.warning('Dropped empty attribute')
    result_observables = list()

    if mal_email:
      observable = self.map_observable_composition(mal_email, event, 'Malicious E-mail', share)
      if observable:
        indicator = self.map_indicator(observable, 'Malicious E-mail', event)
        result_observables.append(observable)
        del mal_email[:]
        if indicator:
          event.indicators.append(indicator)

    if artifacts:
      observable = self.map_observable_composition(artifacts, event, 'Malware Artifacts', share)
      if observable:
        indicator = self.map_indicator(observable, 'Malware Artifacts', event)
        del artifacts[:]
        result_observables.append(observable)
        if indicator:
          event.indicators.append(indicator)

    if ips:
      observable = self.map_observable_composition(ips, event, 'IP Watchlist', share)
      if observable:
        indicator = self.map_indicator(observable, 'IP Watchlist', event)
        del ips[:]
        result_observables.append(observable)
        if indicator:
          event.indicators.append(indicator)

    if file_hashes:
      observable = self.map_observable_composition(file_hashes, event, 'File Hash Watchlist', share)
      if observable:
        indicator = self.map_indicator(observable, 'File Hash Watchlist', event)
        del file_hashes[:]
        result_observables.append(observable)
        if indicator:
          event.indicators.append(indicator)

    if domains:
      observable = self.map_observable_composition(domains, event, 'Domain Watchlist', share)
      if observable:
        indicator = self.map_indicator(observable, 'Domain Watchlist', event)
        del domains[:]
        result_observables.append(observable)
        if indicator:
          event.indicators.append(indicator)

    if c2s:
      observable = self.map_observable_composition(c2s, event, 'C2', share)
      if observable:
        indicator = self.map_indicator(observable, 'C2', event)
        del c2s[:]
        result_observables.append(observable)
        if indicator:
          event.indicators.append(indicator)

    if urls:
      observable = self.map_observable_composition(urls, event, 'URL Watchlist', share)
      if observable:
        indicator = self.map_indicator(observable, 'URL Watchlist', event)
        del urls[:]
        result_observables.append(observable)
        if indicator:
          event.indicators.append(indicator)

    if others:
      observable = self.map_observable_composition(others, event, 'Others', share)
      if observable:
        indicator = self.map_indicator(observable, None, event)
        del others[:]
        result_observables.append(observable)
        if indicator:
          event.indicators.append(indicator)

    if result_observables:
      return result_observables
    else:
      self.syslogger.warning('Event {0} does not contain attributes. None detected'.format(event.identifier))
      return result_observables

  def parse_events(self, xml):
    events = xml.iterfind('./Event')
    rest_events = []

    for event in events:
      rest_event = Event()

      event_id = self.set_event_header(event, rest_event)

      observables = self.parse_attributes(rest_event, event)
      rest_event.observables = observables
      # Append reference

      result = list()

      report = Report()
      report.identifier = uuid4()
      self.set_extended_logging(report, rest_event)
      value = u'{0}{1} Event ID {2}'.format('', self.tag, event_id)
      reference = self.create_reference(uuid4(), None, 'reference_external_identifier', value, None, None, False, False, rest_event)
      report.references.append(reference)
      value = u'{0}/events/view/{1}'.format(self.api_url, event_id)
      reference = self.create_reference(uuid4(), None, 'link', value, None, None, False, False, rest_event)
      report.references.append(reference)

      result.append(report)

      # check if there aren't any empty reports

      for event_report in rest_event.reports:
        if event_report.references:
          continue
        else:
          result.append(event_report)

      rest_event.reports = result
      setattr(rest_event, 'misp_id', event_id)
      rest_events.append(rest_event)

    return rest_events

  def set_extended_logging(self, instance, event):
    instance.creator_group = event.creator_group
    instance.created_at = DatumZait.utcnow()
    instance.modified_on = DatumZait.utcnow()
    instance.modifier = event.creator_group
    instance.originating_group = instance.creator_group

  def get_xml_event(self, event_id):
    url = '{0}/events/{1}'.format(self.api_url, event_id)

    req = urllib2.Request(url, None, self.api_headers)
    xml_string = urllib2.urlopen(req).read()
    return xml_string

  def get_event_from_xml(self, xml_string):
    xml = et.fromstring(xml_string)
    rest_events = self.parse_events(xml)
    return rest_events[0]

  def __get_dump_path(self, base, dirname):
    sub_path = '{0}/{1}/{2}'.format(DatumZait.now().year,
                                    DatumZait.now().month,
                                    DatumZait.now().day)
    if self.file_location:
      path = '{0}/{1}/{2}'.format(base, sub_path, dirname)
      if not isdir(path):
        makedirs(path)
      return path
    else:
      message = 'Dumping of files was activated but no file location was specified'
      self.syslogger.error(message)
      raise MispConverterException(message)

  def __dump_files(self, dirname, filename, data):
      path = self.__get_dump_path(self.file_location, dirname)
      full_path = '{0}/{1}'.format(path, filename)
      if isfile(full_path):
        remove(full_path)
      f = open(full_path, 'w+')
      f.write(data)
      f.close()

  def get_event(self, event_id):
    print u'Getting event {0} - {1}/events/view/{0}'.format(event_id, self.api_url)
    xml_string = self.get_xml_event(event_id)
    rest_event = self.get_event_from_xml(xml_string)

    if self.dump:
      event_uuid = rest_event.identifier
      self.__dump_files(event_uuid, 'Event-{0}.xml'.format(event_id), xml_string)
    return rest_event

  def map_indicator(self, observable, indicator_type, event):
    indicator = Indicator()
    indicator.identifier = uuid4()
    self.set_extended_logging(indicator, event)

    indicator.event = event
    indicator.event_id = event.identifier

    if indicator_type:
      indicator.type_.append(self.get_indicator_type(indicator_type))

    new_observable = clone_observable(observable)
    if new_observable:
      indicator.observables.append(new_observable)
    else:
      return None

    return indicator

  def __parse_event_list(self, xml_sting):
    xml = et.fromstring(xml_sting)

    event_list = {}

    for event in xml.iter(tag='Event'):
      event_id_element = event.find('id')

      if event_id_element is not None:
        event_id = event_id_element.text
        if event_id not in event_list:
          event_list[event_id] = {}
        else:
          message = 'Event collision, API returned the same event twice, should not happen!'
          self.syslogger.error(message)
          raise ValueError(message)

        for event_id_element in event:
          event_list[event_id][event_id_element.tag] = event_id_element.text
    return event_list

  def get_recent_events(self, limit=20, unpublished=False):
    url = '{0}/events/index/sort:date/direction:desc/limit:{1}'.format(self.api_url, limit)
    req = urllib2.Request(url, None, self.api_headers)
    xml_sting = urllib2.urlopen(req).read()

    result = list()

    for event_id, event in self.__parse_event_list(xml_sting).items():
      if event['published'] == '0' and not unpublished:
        continue
      event = self.get_event(event_id)
      result.append(event)

    return result

  def fetch_attachment(self, attribute_id, uuid, event_uuid, filename):
    url = '{0}/attributes/download/{1}'.format(self.api_url, attribute_id)
    try:
      result = None
      req = urllib2.Request(url, None, self.api_headers)
      resp = urllib2.urlopen(req).read()
      binary = StringIO(resp)
      zip_file = ZipFile(binary)
      zip_file.setpassword('infected'.encode('utf-8'))
      if self.dump:

        path = self.__get_dump_path(self.file_location, event_uuid)
        destination_folder = '{0}/{1}'.format(path, '')
        if not isdir(destination_folder):
          makedirs(destination_folder)
        # save zip file

        f = open('{0}/{1}.zip'.format(destination_folder, filename), 'w+')
        f.write(resp)
        f.close()
        extraction_destination = '{0}/{1}.zip_contents'.format(destination_folder, filename)
        if not isdir(extraction_destination):
          makedirs(extraction_destination)
        # unzip the file
        zip_file.extractall(extraction_destination)

      # do everything in memory
      zipfiles = zip_file.filelist

      for zipfile in zipfiles:
        filename = zipfile.filename
        result = zip_file.read(filename)
        break

      zip_file.close()
      return result
    except urllib2.HTTPError:
      return None

  def get_indicator_type(self, indicator_type):
    for type_ in self.indicator_types:
      if type_.name == indicator_type:
        return type_
    message = u'Indicator type {0} is not defined'.format(indicator_type)
    self.syslogger.error(message)
    raise MispMappingException(message)
