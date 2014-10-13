# -*- coding: utf-8 -*-

"""
(Description)

Created on Aug 1, 2014
"""
from ce1sus_api.adapter.stix_cybox.common import StixMapperException, CyboxNotMappableException
from ce1sus_api.adapter.stix_cybox.ce1sus_cybox_mapper import CyboxMapper, OPERATOR_OR
import uuid

from cybox.core.observable import ObservableComposition
from cybox.objects.address_object import Address
from cybox.objects.email_message_object import Attachments
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from stix.common import InformationSource, Identity
from stix.common.confidence import Confidence
from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.indicator import Indicator
from stix.indicator.valid_time import ValidTime
from stix.ttp import TTP, Behavior
from stix.ttp.malware_instance import MalwareInstance


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


INDICATOR_OBS_RELATION = "Child_Of"


class Ce1susStixMapper(object):

  def __init__(self):
    self.cybox_mapper = CyboxMapper()
    self.seen_groups = dict()
    self.seen_uuids = dict()

  def create_ttp(self, title):
    ttp = TTP(title=title)
    return ttp

  def create_observable(self, obj, cybox_obj):
    seen = self.seen_uuids.get(obj.uuid, None)
    if seen:
      new_uuid = uuid.uuid4()
      self.seen_uuids[new_uuid] = True
      self.cybox_mapper.create_observable(obj.definition.name, new_uuid, cybox_obj)
    else:
      self.seen_uuids[obj.uuid] = True
      return self.cybox_mapper.create_observable(obj.definition.name, obj.uuid, cybox_obj)

  def create_email(self, stix_package, obj, parent=None, indicator_parent=None):
    # Create observable composition with email and its children
    if 'email' in obj.definition.name:
      ttp = None
      # indicators and observables
      # Create Toplevel observerable
      cybox_email = self.cybox_mapper.get_blank_email_message()
      iocs = list()
      # create email observable and extract iocs
      for attr in obj.attributes:
        if attr.ioc == '1' or attr.ioc == 1:
          iocs.append(attr)
        if attr.definition.name == 'email_type':
          ttp = self.create_ttp(attr.value)
        else:
          self.cybox_mapper.populate_email_cybox(cybox_email, attr)

      email_observable = self.create_observable(obj, cybox_email)
      stix_package.add_observable(email_observable)
      # create TTP and indicators

      indicator_observables = list()
      for attr in iocs:
        cybox_obj = self.cybox_mapper.get_blank_email_message()
        self.cybox_mapper.populate_email_cybox(cybox_obj, attr)
        observable = self.create_observable(attr, cybox_obj)
        cybox_obj.add_related(cybox_email, INDICATOR_OBS_RELATION, inline=False)
        indicator_observables.append(observable)

      # self.__post_processing(obj, cybox_obj, "Malicious E-mail", "Contained_Within", stix_package, indicator_observables, ttp, indicator_parent, cybox_parent_relation_tuple)
      self.__post_processing(obj, cybox_email, ttp, stix_package, indicator_observables, "Malicious E-mail", indicator_parent)
      self.__set_parent_child_relation(parent, cybox_email)
      return cybox_email
    else:
      return None

  def create_file(self, stix_package, obj, parent=None, indicator_parent=None):
    if 'file' in obj.definition.name:
      malware = None
      # there is a file attached create cybox file
      cybox_file = self.cybox_mapper.get_blank_file()
      iocs = list()
      # create email observable and extract iocs
      if obj.attributes:
        for attr in obj.attributes:
          if attr.ioc == '1' or attr.ioc == 1:
            iocs.append(attr)
          if attr.definition.name == 'malware_type' or attr.definition.name == 'malware_name':
            if not malware:
              malware = MalwareInstance()
            if attr.definition.name == 'malware_name':
              malware.title = attr.value
              malware.add_name(attr.value)
            if attr.definition.name == 'malware_type':
              malware.add_type(attr.value)
          else:
            self.cybox_mapper.populate_file_cybox(cybox_file, attr)

      if parent:
        if hasattr(parent, 'attachments'):
          if not parent.attachments:
            parent.attachments = Attachments()
          parent.attachments.append(cybox_file.parent.id_)

      ttp = None
      if malware:
        ttp = self.create_ttp(malware.title)
        ttp.behavior = Behavior()
        ttp.behavior.add_malware_instance(malware)
        stix_package.add_ttp(ttp)

      # create indicators
      indicator_observables = list()
      for attr in iocs:
        cybox_obj = self.cybox_mapper.get_blank_file()
        self.cybox_mapper.populate_file_cybox(cybox_obj, attr)
        observable1 = self.create_observable(attr, cybox_obj)
        cybox_obj.add_related(cybox_file, INDICATOR_OBS_RELATION, inline=False)
        indicator_observables.append(observable1)

      # self.__post_processing(obj, cybox_file, "Malware Artifacts", "Extracted_from", stix_package, indicator_observables, ttp, indicator_parent, (cybox_file, "Related_To"))
      self.__post_processing(obj, cybox_file, ttp, stix_package, indicator_observables, "Malware Artifacts", indicator_parent)
      self.__set_parent_child_relation(parent, cybox_file)
      return cybox_file
    else:
      return None

  def __set_parent_child_relation(self, parent, child):
    if parent:
      parent_child_relation = self.cybox_mapper.get_relation(parent, child)
      parent.parent.add_related(child, parent_child_relation, inline=False)
      child.parent.add_related(parent, self.cybox_mapper.get_inverse_relation(parent_child_relation), inline=False)

  def __post_processing(self, obj, cybox_obj, ttp, stix_package, indicator_observables, indicator_type, indicator_parent):
    """
    Last steps to be taken for all objects
    """
    # if ttp add
    if ttp:
        stix_package.add_ttp(ttp)
    indicator = None
    # create found indicators
    if indicator_observables:
      indicator = self.create_indicator(None, ttp, obj, indicator_type)
      for observable in indicator_observables:
        indicator.add_observable(observable)
      indicator.title = u'{0} Composed Indicators'.format(obj.definition.name)

    # add relation to indicator
    if indicator:
      if indicator_parent:
        indicator_parent.add_related_indicator(Indicator(idref=indicator.id_))
      stix_package.add_indicator(indicator)
    if obj:
      # search for their children
      if obj.children:
        for child in obj.children:
          stix_object = self.create_stix_object(stix_package, child, cybox_obj, indicator)
          if not stix_object:
            raise Exception('"{0}" child not mappable of object "{1}"'.format(child.name, obj.name))
    if cybox_obj:
      # Create observable out of object
      observable = self.create_observable(obj, cybox_obj)
      stix_package.add_observable(observable)

  def set_properties(self, stix_indicator, attribute):
    valid_time = ValidTime(start_time=attribute.created, end_time=attribute.created)
    description = 'Description'
    confidence = Confidence('High')

    stix_indicator.description = description
    stix_indicator.add_valid_time_position(valid_time)
    stix_indicator.confidence = confidence

  def create_ioc_records(self, stix_package, obj, parent=None, indicator_parent=None):
    # create a composed attribute for IOC and Observables
    ioc_comp_obs = ObservableComposition()
    ioc_comp_obs.operator = ObservableComposition.OPERATOR_OR
    fh_comp_obs = ObservableComposition()
    fh_comp_obs.operator = ObservableComposition.OPERATOR_OR

    dom_comp_obs = ObservableComposition()
    dom_comp_obs.operator = ObservableComposition.OPERATOR_OR

    ip_comp_obs = ObservableComposition()
    ip_comp_obs.operator = ObservableComposition.OPERATOR_OR

    url_comp_obs = ObservableComposition()
    url_comp_obs.operator = ObservableComposition.OPERATOR_OR

    comp_obs = ObservableComposition()
    comp_obs.operator = ObservableComposition.OPERATOR_OR

    for attribute in obj.attributes:
      try:
        gen_cybox = self.cybox_mapper.create_generic_cybox(attribute)
        observable = self.cybox_mapper.create_observable(attribute.definition.name, attribute.uuid, gen_cybox)
        if attribute.ioc == '1' or attribute.ioc == 1:
          if isinstance(gen_cybox, File):
            if gen_cybox.hashes:
              fh_comp_obs.add(observable)
            else:
              ioc_comp_obs.add(observable)
          elif isinstance(gen_cybox, Address):
            ip_comp_obs.add(observable)
          elif isinstance(gen_cybox, URI):
            if gen_cybox.type_ == URI.TYPE_DOMAIN:
              dom_comp_obs.add(observable)
            elif gen_cybox.type_ == URI.TYPE_URL:
              url_comp_obs.add(observable)
            else:
              ioc_comp_obs.add(observable)
        else:
          comp_obs.add(observable)

      except CyboxNotMappableException as error:
        print error.message
    if len(fh_comp_obs.observables) > 0:
      indicator = self.create_indicator(fh_comp_obs, None, obj, "File Hash Watchlist")
      stix_package.add_indicator(indicator)

    if len(ip_comp_obs.observables) > 0:
      indicator = self.create_indicator(ip_comp_obs, None, obj, "IP Watchlist")
      stix_package.add_indicator(indicator)

    if len(dom_comp_obs.observables) > 0:
      indicator = self.create_indicator(dom_comp_obs, None, obj, "Domain Watchlist")
      stix_package.add_indicator(indicator)

    if len(url_comp_obs.observables) > 0:
      indicator = self.create_indicator(url_comp_obs, None, obj, "URL Watchlist")
      stix_package.add_indicator(indicator)

    if len(ioc_comp_obs.observables) > 0:
      indicator = self.create_indicator(ioc_comp_obs, None, obj)
      stix_package.add_indicator(indicator)

    if len(comp_obs.observables) > 0:
      stix_package.add_observable(comp_obs)
    self.__post_processing(obj, None, None, stix_package, None, None, None)
    self.__set_parent_child_relation(parent, gen_cybox)
    return True

  def create_stix_object(self, stix_package, obj, parent=None, indicator_parent=None):
    stix_object = None
    if obj.definition.name == 'email':
      stix_object = self.create_email(stix_package, obj, parent, indicator_parent)
    elif 'file' in obj.definition.name:
      stix_object = self.create_file(stix_package, obj, parent, indicator_parent)
    elif obj.definition.name == 'forensic_records':
      raise StixMapperException('Forensic records is not implemented')
    elif obj.definition.name == 'malicious_website':
      raise StixMapperException('Malicious website is not implemented')
    elif obj.definition.name == 'network_traffic':
      raise StixMapperException('Network traffic is not implemented')
    elif obj.definition.name == 'reference_document':
      # References are not supported by STIX
      print 'Reference document is not supported'
      stix_object = True
    elif obj.definition.name == 'references':
      # References are not supported by STIX
      print 'References is not supported'
      stix_object = True
    elif obj.definition.name == 'source_code':
      raise StixMapperException('Source code is not implemented')
    elif obj.definition.name == 'user_account':
      raise StixMapperException('User account is not implemented')
    elif obj.definition.name == 'ioc_records':
      stix_object = self.create_ioc_records(stix_package, obj, parent, indicator_parent)
    return stix_object

  def create_indicator(self, cybox_object, ttp, attribute, indicator_type=None):
    indicator = Indicator()
    indicator.id_ = 'ce1sus:Indicator1-{0}'.format(attribute.uuid)
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
    self.set_properties(indicator, attribute)
    return indicator

  def create_stix_identity(self, obj):
    idenfitier = 'ce1sus:Group-{0}'.format(obj.group.uuid)
    identity = self.seen_groups.get(idenfitier, None)
    if identity:
      identity = Identity()
      identity.refid = idenfitier
    else:
      identity = Identity()
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

    # Add TLP
    marking = Marking()
    marking_spec = MarkingSpecification()
    marking.add_marking(marking_spec)

    tlp_marking_struct = TLPMarkingStructure()
    tlp_marking_struct.color = event.tlp.upper()
    tlp_marking_struct.marking_model_ref = 'http://govcert.lu/en/docs/POL_202_V2.2_rfc2350.pdf'
    marking_spec.marking_structures = list()
    marking_spec.marking_structures.append(tlp_marking_struct)
    stix_header.handling = marking

    for obj in event.objects:
      detected = self.create_stix_object(stix_package, obj)
      if not detected:
        raise Exception('Event object "{0}" not mappable'.format(obj.definition.name))
    return stix_package
