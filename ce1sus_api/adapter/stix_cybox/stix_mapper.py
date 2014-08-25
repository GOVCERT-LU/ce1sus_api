# -*- coding: utf-8 -*-

"""
(Description)

Created on Aug 1, 2014
"""

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'

from stix.incident.time import Time as StixTime
from stix.ttp.infrastructure import Infrastructure
from stix.ttp.resource import Resource
from stix.ttp import TTP, Behavior
from stix.common.related import RelatedTTP
from stix.indicator import Indicator
from stix.core import STIXPackage, STIXHeader
from stix.common import StructuredText, VocabString, InformationSource, Statement, Identity, RelatedObservable
from stix.incident import Incident
from ce1sus_api.adapter.stix_cybox.cybox_mapper import CyboxMapper, OPERATOR_OR
from stix.ttp.malware_instance import MalwareInstance


from datetime import datetime
from dateutil.tz import tzutc


class StixMapper(object):

  def __init__(self):
    self.cybox_mapper = CyboxMapper()
    self.seen_groups = dict()

  def create_Email(self, stix_package, obj, parent=None):
    if 'email' in obj.definition.name:
      ttp = None
      # indicators and observables
      # Create Toplevel observerable
      cybox_email = self.cybox_mapper.get_blank_email_message()
      for attr in obj.attributes:
        if attr.definition.name == 'email_type':
          ttp = TTP(title=attr.value)
        else:
          cybox_email = self.cybox_mapper.create_email_cybox(cybox_email, obj, attr)

      observable = self.cybox_mapper.create_observable(obj, cybox_email)
      stix_package.add_observable(observable)
      # create TTP and indicators

      indicator_observables = list()
      for attr in obj.attributes:
        if attr.ioc == '1' or attr.ioc == 1:
          cybox_obj = self.cybox_mapper.create_email_cybox(self.cybox_mapper.get_blank_email_message(), obj, attr)
          observable = self.cybox_mapper.create_observable(attr, cybox_obj)
          indicator_observables.append(observable)
      if indicator_observables:
        indicator = self.create_indicator(None, ttp, obj, "Malicious E-mail")
        for observable in indicator_observables:
          indicator.add_observable(observable)

        indicator.title = u'{0} Composed Indicators'.format(obj.definition.name)

        stix_package.add_indicator(indicator)
      if ttp:
        stix_package.add_ttp(ttp)
      # create subitems for email

      # def check if there are child objects
      for child in obj.children:
        detected = self.create_stix_object(stix_package, child, cybox_email)
        if not detected:
          raise Exception('Not mappable')
      return True
    else:
      return False

  def create_file(self, stix_package, obj, parent=None):
    if 'file' in obj.definition.name:
      malware = None
      # there is a file attached create cybox file
      cybox_file = self.cybox_mapper.get_blank_file()
      for attr in obj.attributes:
        if attr.definition.name == 'malware_type' or attr.definition.name == 'malware_name':
          if not malware:
            malware = MalwareInstance()
          if attr.definition.name == 'malware_name':
            malware.title = attr.value
            malware.add_name(attr.value)
          if attr.definition.name == 'malware_type':
            malware.add_type(attr.value)
        else:
          cybox_file = self.cybox_mapper.create_file_cybox(cybox_file, obj, attr)
      if parent:
        parent.add_related(cybox_file, "Contains", inline=True)
      if malware:
        f_ttp = TTP(title=malware.title)
        f_ttp.behavior = Behavior()
        f_ttp.behavior.add_malware_instance(malware)
        stix_package.add_ttp(f_ttp)

      # create indicators
      indicator_observables1 = list()
      for attr in obj.attributes:
        if attr.ioc == '1' or attr.ioc == 1:
          cybox_obj = self.cybox_mapper.create_file_cybox(self.cybox_mapper.get_blank_file(), obj, attr)
          observable1 = self.cybox_mapper.create_observable(attr, cybox_obj)
          indicator_observables1.append(observable1)
      if indicator_observables1:
        indicator2 = self.create_indicator(None, f_ttp, obj, "Malware Artifacts")
        for observable in indicator_observables1:
          indicator2.add_observable(observable)
        indicator2.title = u'{0} Composed Indicators'.format(obj.definition.name)
        stix_package.add_indicator(indicator2)
      for child in obj.children:
        detected = self.create_stix_object(stix_package, child, indicator2)
        if not detected:
          raise Exception('Not mappable')
      return True
    else:
      return False

  def create_ioc_records(self, stix_package, obj, parent=None):

    for attribute in obj.attributes:
      gen_cybox = self.cybox_mapper.create_generic_cybox(attribute)
      if attribute.ioc == '1' or attribute.ioc == 1:
        indicator2 = self.create_indicator(gen_cybox, None, obj)
        stix_package.add_indicator(indicator2)
      else:
        observable1 = self.cybox_mapper.create_observable(attribute, gen_cybox)
        stix_package.add_observable(observable1)
    return True

  def create_stix_object(self, stix_package, obj, parent=None):
    created = False
    if not created and obj.definition.name == 'email':
      created = self.create_Email(stix_package, obj)
    if not created and 'file' in obj.definition.name:
      created = self.create_file(stix_package, obj, parent=None)
    if not created and obj.definition.name == 'forensic_records':
      pass
    if not created and obj.definition.name == 'malicious_website':
      pass
    if not created and obj.definition.name == 'network_traffic':
      pass
    if not created and obj.definition.name == 'reference_document':
      pass
    if not created and obj.definition.name == 'references':
      pass
    if not created and obj.definition.name == 'source_code':
      pass
    if not created and obj.definition.name == 'user_account':
      pass
    if not created and obj.definition.name == 'ioc_records':
      created = self.create_ioc_records(stix_package, obj, parent=None)
    return created

  def create_indicator(self, cybox_object, ttp, attribute, indicator_type=None):
    indicator = Indicator()
    indicator.id_ = 'ce1sus:Indicator-{0}'.format(attribute.uuid)
    indicator.title = attribute.definition.name
    indicator.observable_composition_operator = OPERATOR_OR
    # Todo Add confidence
    # indicator_attachment.confidence = "Low"
    creator = self.create_stix_identity(attribute)
    time = self.cybox_mapper.get_time(produced_time=attribute.created)
    info_source = InformationSource(identity=creator, time=time)
    indicator.producer = info_source
    if cybox_object:
      indicator.observable = cybox_object
      indicator.observable.title = attribute.definition.name
    # Todo Add Type
    if indicator_type:
      indicator.add_indicator_type(indicator_type)

    if ttp:
      indicator.add_indicated_ttp(TTP(idref=ttp.id_))

    return indicator

  def create_stix_identity(self, obj):
    idenfitier = 'ce1sus:Group-{0}'.format(obj.group.uuid)
    identity = self.seen_groups.get(idenfitier, None)
    if identity:
      identity = Identity()
      identity.refid = idenfitier
    else:
      identity = Identity()
      # TODO: Add uuid to this
      identity.id_ = idenfitier
      identity.name = obj.group.name
      self.seen_groups[idenfitier] = True
    return identity

  def create_stix_indicator(self, obj):
    pass

  def create_stix_package(self, event):
    stix_package = STIXPackage()
    stix_package.id_ = 'ce1sus:Event-{0}'.format(event.uuid)
    stix_header = STIXHeader(title=event.title)
    stix_header.description = event.description

    identifiy = self.create_stix_identity(event)
    time = self.cybox_mapper.get_time(produced_time=event.created, received_time=event.modified)
    info_source = InformationSource(identity=identifiy, time=time)
    stix_header.information_source = info_source
    stix_package.stix_header = stix_header

    for obj in event.objects:
      detected = self.create_stix_object(stix_package, obj)
      if not detected:
        raise Exception('Not mappable')
    return stix_package
