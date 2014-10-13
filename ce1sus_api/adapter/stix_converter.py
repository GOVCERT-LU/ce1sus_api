# -*- coding: utf-8 -*-

"""
(Description)

Created on Jul 30, 2014
"""
from ce1sus_api.adapter.stix_cybox.ce1sus_stix_mapper import Ce1susStixMapper
from ce1sus_api.adapter.stix_cybox.stix_ce1sus_mapper import StixCe1susMapper
import cybox.utils.idgen
from cybox.utils.nsparser import Namespace
import stix.utils.idgen


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class StixConverter(object):

  def __init__(self, ce1sushost):
    cybox.utils.idgen.set_id_namespace(Namespace(ce1sushost, 'ce1sus'))
    stix.utils.idgen.set_id_namespace({ce1sushost: 'ce1sus'})
    self.stix_mapper = Ce1susStixMapper()
    self.ce1sus_mapper = StixCe1susMapper()

  def create_stix_xml(self, event):
    stix_package = self.stix_mapper.create_stix_package(event)
    return stix_package.to_xml()

  def create_ce1sus_event(self, stix_package):
    return self.ce1sus_mapper.create_event(stix_package)
