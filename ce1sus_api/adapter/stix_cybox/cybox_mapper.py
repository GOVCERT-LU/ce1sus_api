# -*- coding: utf-8 -*-

"""
(Description)

Created on Aug 1, 2014
"""

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'
from cybox.objects.link_object import Link
from cybox.objects.mutex_object import Mutex
from cybox.objects.hostname_object import Hostname
from cybox.objects.uri_object import URI
from cybox.objects.file_object import File
from cybox.objects.email_message_object import EmailMessage, EmailRecipients, EmailHeader, Attachments
from cybox.objects.code_object import Code
from cybox.objects.user_account_object import UserAccount
from cybox.objects.win_registry_key_object import WinRegistryKey
from cybox.objects.domain_name_object import DomainName
from cybox.core import Observable, ObservableComposition, Observables, Object, Event
from cybox.common.time import Time
from cybox.common import Hash
from cybox.objects.address_object import EmailAddress
from ce1sus_api.adapter.stix_cybox.common import CyboxMapperException


OPERATOR_OR = ObservableComposition.OPERATOR_OR


class CyboxMapper(object):

  DIRECT_MAPPING = {'reference_url': Link,
                    'mutex': Mutex,
                    'hostname': Hostname,
                    'url': URI,
                    'win_registry_key': WinRegistryKey,
                    'domain': DomainName
                    }

  def create_observable(self, object, cybox_object):
    # observable_composition = ObservableComposition(ObservableComposition.OPERATOR_OR)
    observable = Observable(cybox_object)
    # observable.observable_composition = observable_composition
    observable.title = object.definition.name
    observable.id_ = 'ce1sus:Observable-{0}'.format(object.uuid)
    return observable

  def create_observable_cybox(self, obj):
    observable = Observable(title=obj.definition.name, description=None)
    observable.id_ = 'ce1sus:Object-{0}'.format(obj.uuid)
    composition = ObservableComposition()
    # TODO include operators
    composition.operator = 'OR'
    composition.id_ = 'ce1sus:ObjectCompsition-{0}'.format(obj.uuid)
    if  obj.attributes:
      for attr in obj.attributes:
          cybox_obj = self.create_email_cybox(obj)
          attr_observable = self.create_observable(attr, cybox_obj)
          attr_observable.id_ = 'ce1sus:Attribute-{0}'.format(attr.uuid)
          composition.add(attr_observable)
    observable.observable_composition = composition
    return observable

  def create_generic_cybox(self, attribute):
    # This creates a cybox object for the attributes where a one to one mapping is possible
    clazz = CyboxMapper.DIRECT_MAPPING.get(attribute.definition.name, None)
    if clazz:
      instance = clazz()
      instance.value = attribute.value
      return instance
    return None

  def set_check_attr(self, cybox_obj, proerty_name, value,):
    # TODO make this correct
    cybox_value = None
    if '.' in proerty_name:
      properies = proerty_name.split('.')
      prop1 = getattr(cybox_obj, properies[0])
      if prop1:
        cybox_value = getattr(prop1, properies[1])
      else:
        pass
    else:
      cybox_value = getattr(cybox_obj, proerty_name, None)
    if cybox_value:
      cybox_value.condition = "Equals"
    else:
      setattr(cybox_obj, proerty_name, value)
      cybox_value = getattr(cybox_obj, proerty_name, None)
      cybox_value.condition = "Equals"

  def create_file_cybox(self, cybox_file, obj, attribute):
    # returns a cybox file object out of a ce1sus object
    def_name = obj.definition.name
    if def_name == 'executable_file' or def_name == 'generic_file' or def_name == 'ioc_records' or True:

      def_name = attribute.definition.name
      if def_name == 'digital_signature':
        # check if not already set
        raise CyboxMapperException('Not defined')
      elif def_name == 'encryption_mechanism':
        self.set_check_attr(cybox_file, 'encryption_mechanism', attribute.value)
      elif def_name == 'file_accessed_datetime':
        self.set_check_attr(cybox_file, 'file_accessed_datetime', attribute.value)
      elif def_name == 'file_created_datetime':
        self.set_check_attr(cybox_file, 'file_created_datetime', attribute.value)
      elif def_name == 'file_extension':
        self.set_check_attr(cybox_file, 'file_created_datetime', attribute.value)
      elif def_name == 'file_full_path':
        # check if not already set
        raise CyboxMapperException('Not defined')
      elif def_name == 'file_full_path_pattern':
        # check if not already set
        raise CyboxMapperException('Not defined')
        # TODO: set different condifiion
      elif def_name == 'file_modified_time':
        self.set_check_attr(cybox_file, 'file_modified_time', attribute.value)
      elif def_name == 'file_name' or def_name == 'email_attachment_file_name':
        self.set_check_attr(cybox_file, 'file_name', attribute.value)
        cybox_file.file_name.condition = "Equals"
      elif def_name == 'file_name_pattern':
        self.set_check_attr(cybox_file, 'file_name', attribute.value)
        cybox_file.file_name.condition = "Like"
      elif 'hash' in def_name:
        cybox_file.add_hash(attribute.value)
      elif def_name == 'magic_number':
        raise CyboxMapperException('Not defined')
      elif def_name == 'size_in_bytes':
        self.set_check_attr(cybox_file, 'size', attribute.value)
      elif def_name == 'file_extension':
        self.set_check_attr(cybox_file, 'file_extension', attribute.value)
        cybox_file.file_extension.condition = "Equals"
      elif def_name == 'raw_file':
        print "raw_file is not supported"
      elif def_name == 'mime_type':
        print "raw_file is not supported"
      elif def_name == 'file_id':
        print "raw_file is not supported"
      else:
        raise CyboxMapperException('Not defined for {0}'.format(def_name))
      return cybox_file
    else:
      return None

  def create_email_cybox(self, cybox_file, obj, attribute):
    # returns a cybox email object out of a ce1sus object
    def_name = obj.definition.name
    if def_name == 'email' or def_name == 'ioc_records':
      def_name = attribute.definition.name

      if not cybox_file.header:
        cybox_file.header = EmailHeader()
      if def_name == 'email_attachment_file_name':
        if not cybox_file.attachments:
          cybox_file.attachments = Attachments()
          attached_file_object = self.create_file_cybox(File(), obj, attribute)
          # cybox_file.add_related(attached_file_object, "Contains", inline=True)
          cybox_file.attachments.append(attached_file_object.parent.id_)

      elif def_name == 'email_bcc':
        if not cybox_file.header.bcc:
          cybox_file.header.bcc = EmailRecipients()
        cybox_file.header.bcc.append(self.create_EmailAddress(attribute))
      elif def_name == 'email_cc':
        if not cybox_file.header.cc:
          cybox_file.header.cc = EmailRecipients()
        cybox_file.header.bcc.append(self.create_EmailAddress(attribute))
      elif def_name == 'email_errors_to':
        self.set_check_attr(cybox_file, 'header.errors_to', attribute.value)
      elif def_name == 'email_message_id':
        self.set_check_attr(cybox_file, 'header.message_id', attribute.value)
      elif def_name == 'email_mime_version':
        self.set_check_attr(cybox_file, 'header.mime_version', attribute.value)
      elif def_name == 'email_raw_body':
        self.set_check_attr(cybox_file, 'raw_body', attribute.value)
      elif def_name == 'email_raw_header':
        self.set_check_attr(cybox_file, 'raw_header', attribute.value)
      elif def_name == 'email_reply_to':
        if not cybox_file.header.in_reply_to:
          cybox_file.header.in_reply_to = EmailRecipients()
        cybox_file.header.in_reply_to.append(self.create_EmailAddress(attribute))
      elif def_name == 'email_server':
        self.set_check_attr(cybox_file, 'email_server', attribute.value)
      elif def_name == 'email_subject':
        self.set_check_attr(cybox_file, 'subject', attribute.value)
      elif def_name == 'email_from':
        if not cybox_file.header.from_:
          cybox_file.header.from_ = self.create_EmailAddress(attribute)
      elif def_name == 'email_to':
        if not cybox_file.header.to:
          cybox_file.header.to = EmailRecipients()
        cybox_file.header.to.append(self.create_EmailAddress(attribute))
      elif def_name == 'email_x_mailer':
        self.set_check_attr(cybox_file, 'header.x_mailer', attribute.value)
      elif def_name == 'email_x_originating_ip':
        self.set_check_attr(cybox_file, 'header.x_originating_ip', attribute.value)
      elif 'hash' in def_name:
        raise CyboxMapperException('Not defined')
      else:
        raise CyboxMapperException('Not defined for {0}'.format(def_name))
      return cybox_file
    else:
      return None

  def create_EmailAddress(self, attribute):
    email = EmailAddress(attribute.value)
    email.condition = "Equals"
    return email

  def create_http_cybox(self, obj):
    return None

  def create_code_cybox(self, obj):
    def_name = obj.definition.name
    if def_name == 'source_code' or def_name == 'ioc_records':
      cybox_file = Code()
      for attribute in obj.attribtues:
        def_name = attribute.definition.name
        if def_name == 'code_language':
          self.set_check_attr(cybox_file, 'language', attribute.value)
        elif def_name == 'description':
          self.set_check_attr(cybox_file, 'description', attribute.value)
        elif def_name == 'digital_signature':
          raise CyboxMapperException('Not defined')
        elif def_name == 'discovery_method':
          raise CyboxMapperException('Not defined')
        elif def_name == 'processor_family':
          self.set_check_attr(cybox_file, 'processor_family', attribute.value)
        elif def_name == 'targeted_platform':
          raise CyboxMapperException('Not defined')

  def create_user_account_cybox(self, obj):
    def_name = obj.definition.name
    if def_name == 'user_account' or def_name == 'ioc_records':
      cybox_file = UserAccount()
      for attribute in obj.attribtues:
        def_name = attribute.definition.name
        if def_name == 'full_name':
          self.set_check_attr(cybox_file, 'full_name', attribute.value)
        elif def_name == 'username':
          self.set_check_attr(cybox_file, 'username', attribute.value)

  def get_blank_email_message(self):
    email = EmailMessage()
    email.attachments = Attachments()
    return email

  def get_time(self, start_time=None, end_time=None, produced_time=None, received_time=None):
    return Time(start_time, end_time, produced_time, received_time)

  def get_blank_file(self):
    return File()
