# -*- coding: utf-8 -*-

"""
(Description)

Created on Aug 1, 2014
"""
from ce1sus_api.adapter.stix_cybox.common import CyboxMapperException, CyboxMapperDepricatedException, CyboxNotMappableException
from ce1sus_api.adapter.stix_cybox.common import get_parent_child_relation, get_inverse_relation

from cybox.common.time import Time
from cybox.core import Observable, ObservableComposition
from cybox.objects.address_object import EmailAddress
from cybox.objects.artifact_object import Artifact, Base64Encoding
from cybox.objects.code_object import Code
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage, EmailRecipients, EmailHeader, Links
from cybox.objects.file_object import File
from cybox.objects.hostname_object import Hostname
from cybox.objects.link_object import Link
from cybox.objects.mutex_object import Mutex
from cybox.objects.uri_object import URI
from cybox.objects.user_account_object import UserAccount
from cybox.objects.win_registry_key_object import WinRegistryKey


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


OPERATOR_OR = ObservableComposition.OPERATOR_OR


class CyboxMapper(object):

  DIRECT_MAPPING = {'reference_url': Link,
                    'mutex': Mutex,
                    'hostname': Hostname,
                    'url': URI,
                    'win_registry_key': WinRegistryKey,
                    'domain': DomainName,
                    'url_path': URI,
                    'analysis_free_text': True,
                    'hash_sha1': File,
                    'hash_md5': File,
                    'hash_sha256': File,

                    }

  def create_observable(self, tile, uuid, cybox_object):
    # observable_composition = ObservableComposition(ObservableComposition.OPERATOR_OR)
    observable = Observable(cybox_object)
    # observable.observable_composition = observable_composition
    observable.title = tile
    if uuid:
      observable.id_ = 'ce1sus:Observable-{0}'.format(uuid)
    return observable

  def create_observable_cybox(self, obj):
    observable = Observable(title=obj.definition.name, description=None)
    observable.id_ = 'ce1sus:Object-{0}'.format(obj.uuid)
    composition = ObservableComposition()
    # TODO include operators
    composition.operator = 'OR'
    composition.id_ = 'ce1sus:ObjectCompsition-{0}'.format(obj.uuid)
    if obj.attributes:
      for attr in obj.attributes:
          cybox_obj = self.create_email_cybox(obj)
          attr_observable = self.create_observable(attr, cybox_obj)
          attr_observable.id_ = 'ce1sus:Attribute-{0}'.format(attr.uuid)
          composition.add(attr_observable)
    observable.observable_composition = composition
    return observable

  def create_generic_cybox(self, attribute):
    # This creates a cybox object for the attributes where a one to one mapping is possible
    definition = attribute.definition.name
    clazz = CyboxMapper.DIRECT_MAPPING.get(definition, None)
    if clazz is True:
      raise CyboxNotMappableException(u'Mapping of {0} is not avalable in strix'.format(definition))
    elif clazz:
      instance = clazz()
      if isinstance(instance, File):
        cybox_file = self.get_blank_file()
        self.populate_file_cybox(cybox_file, attribute)
        return cybox_file
      else:
        instance.value = attribute.value
        return instance
    else:
      raise CyboxMapperException(u'Direct mapping of "{0}" is not defined'.format(definition))

  def set_check_attr(self, cybox_obj, proerty_name, value, condition="Equals"):
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
      cybox_value.condition = condition
    else:
      setattr(cybox_obj, proerty_name, value)
      cybox_value = getattr(cybox_obj, proerty_name, None)
      cybox_value.condition = condition

  def populate_file_cybox(self, cybox_file, attribute):
    def_name = attribute.definition.name
    if def_name == 'digital_signature':
      # check if not already set
      raise CyboxMapperException('Not defined')
    elif def_name == 'encryption_mechanism':
      self.set_check_attr(cybox_file, 'encryption_algorithm', attribute.value)
    elif def_name == 'file_accessed_datetime':
      self.set_check_attr(cybox_file, 'accessed_time', attribute.value)
    elif def_name == 'file_created_datetime':
      self.set_check_attr(cybox_file, 'created_time', attribute.value)
    elif def_name == 'file_extension':
      self.set_check_attr(cybox_file, 'file_extension', attribute.value)
    elif def_name == 'file_full_path':
      self.set_check_attr(cybox_file, 'full_path', attribute.value)
    elif def_name == 'file_full_path_pattern':
      self.set_check_attr(cybox_file, 'full_path', attribute.value, "like")
    elif def_name == 'file_modified_time':
      self.set_check_attr(cybox_file, 'modified_time', attribute.value)
    elif def_name == 'file_name' or def_name == 'email_attachment_file_name':
      self.set_check_attr(cybox_file, 'file_name', attribute.value)
      cybox_file.file_name.condition = "Equals"
    elif def_name == 'file_name_pattern':
      self.set_check_attr(cybox_file, 'file_name', attribute.value, "like")
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
      raw_file = self.create_raw_file(cybox_file, attribute)
      # Add artifact to parent file (Use inline to combine them completely)
      cybox_file.add_related(raw_file, "Characterizes", inline=True)
    elif def_name == 'mime_type':
      print 'mime_type is not supported for files'
    elif def_name == 'file_id':
      print 'file_id is not supported for files'
    else:
      raise CyboxMapperException('No Attribute "{0}" for populating a file'.format(def_name))

  def get_relation(self, parent_obj, child_obj):
    return get_parent_child_relation(parent_obj, child_obj)

  def get_inverse_relation(self, relation):
    return get_inverse_relation(relation)

  def create_raw_file(self, cybox_file, obj):
    # create package
    artifact = Artifact(data=obj.value[1], type_='File')
    # artifact.packaging.append(ZlibCompression())
    artifact.packaging.append(Base64Encoding())
    return artifact

  def __check_set_email_header(self, cybox_email):
    if not cybox_email.header:
      cybox_email.header = EmailHeader()

  def populate_email_cybox(self, cybox_email, attribute):
    # returns a cybox email object out of a ce1sus object
    def_name = attribute.definition.name

    if def_name == 'email_attachment_file_name':
      raise CyboxMapperDepricatedException(u'email_attachment_file_name is no longer supported use a file object insead.')
    elif def_name == 'email_bcc':
      self.__check_set_email_header(cybox_email)
      if not cybox_email.header.bcc:
        cybox_email.header.bcc = EmailRecipients()
      cybox_email.header.bcc.append(self.create_EmailAddress(attribute))
    elif def_name == 'email_cc':
      self.__check_set_email_header(cybox_email)
      if not cybox_email.header.cc:
        cybox_email.header.cc = EmailRecipients()
      cybox_email.header.bcc.append(self.create_EmailAddress(attribute))
    elif def_name == 'email_errors_to':
      self.__check_set_email_header(cybox_email)
      self.set_check_attr(cybox_email, 'header.errors_to', attribute.value)
    elif def_name == 'email_message_id':
      self.__check_set_email_header(cybox_email)
      self.set_check_attr(cybox_email, 'header.message_id', attribute.value)
    elif def_name == 'email_mime_version':
      self.__check_set_email_header(cybox_email)
      self.set_check_attr(cybox_email, 'header.mime_version', attribute.value)
    elif def_name == 'email_raw_body':
      self.set_check_attr(cybox_email, 'raw_body', attribute.value)
    elif def_name == 'email_raw_header':
      self.set_check_attr(cybox_email, 'raw_header', attribute.value)
    elif def_name == 'email_reply_to':
      if not cybox_email.header.in_reply_to:
        self.__check_set_email_header(cybox_email)
        cybox_email.header.in_reply_to = EmailRecipients()
      cybox_email.header.in_reply_to.append(self.create_EmailAddress(attribute))
    elif def_name == 'email_server':
      self.set_check_attr(cybox_email, 'email_server', attribute.value)
    elif def_name == 'email_subject':
      self.set_check_attr(cybox_email, 'subject', attribute.value)
    elif def_name == 'email_from':
      self.__check_set_email_header(cybox_email)
      if not cybox_email.header.from_:
        cybox_email.header.from_ = self.create_EmailAddress(attribute)
    elif def_name == 'email_to':
      self.__check_set_email_header(cybox_email)
      if not cybox_email.header.to:
        cybox_email.header.to = EmailRecipients()
      cybox_email.header.to.append(self.create_EmailAddress(attribute))
    elif def_name == 'email_x_mailer':
      self.set_check_attr(cybox_email, 'header.x_mailer', attribute.value)
    elif def_name == 'email_x_originating_ip':
      self.set_check_attr(cybox_email, 'header.x_originating_ip', attribute.value)
    elif 'hash' in def_name:
      raise CyboxMapperException('Not defined')
    elif def_name == 'email_link':
      if not cybox_email.links:
        cybox_email.links = Links()
      cybox_email.links.append(Link(attribute.value))
    else:
      raise CyboxMapperException('Not defined for {0}'.format(def_name))

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
    return email

  def get_time(self, start_time=None, end_time=None, produced_time=None, received_time=None):
    return Time(start_time, end_time, produced_time, received_time)

  def get_blank_file(self):
    file_obj = File()

    return file_obj
