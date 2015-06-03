# -*- coding: utf-8 -*-

"""
(Description)

Created on Jan 8, 2015
"""

from ce1sus.api.classes.base import ExtendedLogingInformations, RestBase
from ce1sus.api.classes.common import ValueException, Properties
from ce1sus.api.classes.group import Group
from ce1sus.helpers.common import strings


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'

# Note: This is not yet part of STIX should be on 1.2


class ReferenceDefinition(RestBase):

    def __init__(self):
        RestBase.__init__(self)
        self.name = None
        self.description = None
        self.referencehandler_id = None
        self.share = None
        self.regex = None
        self.chksum = None

    def to_dict(self, complete=True, inflated=False):
        if complete:
            return {'identifier': self.convert_value(self.identifier),
                    'name': self.convert_value(self.name),
                    'description': self.convert_value(self.description),
                    'referencehandler_id': self.convert_value(self.referencehandler_id),
                    'share': self.convert_value(self.share),
                    'regex': self.convert_value(self.regex),
                    'chksum': self.convert_value(self.chksum),
                    }
        else:
            return {'identifier': self.identifier,
                    'name': self.name
                    }

    def populate(self, json):
        self.identifier = json.get('identifier', None)
        self.name = json.get('name', None)
        self.description = json.get('description', None)
        self.referencehandler_id = json.get('referencehandler_id', None)
        share = json.get('share', False)
        self.share = share
        self.regex = json.get('regex', None)


class Reference(ExtendedLogingInformations):

    def __init__(self):
        ExtendedLogingInformations.__init__(self)
        self.definition_id = None
        self.definition = None
        self.value = None
        self.properties = Properties('0')
        self.report_id = None
        self.report = None

    def to_dict(self, complete=True, inflated=False):
        if isinstance(self.value, ReferenceFile):
            value = self.value.to_dict()
        else:
            value = self.convert_value(self.value)

        creator = None
        if self.creator_group:
            creator = self.creator_group.to_dict(False, False)
        modifier = None
        if self.modifier:
            modifier = self.modifier.to_dict(False, False)

        return {'identifier': self.convert_value(self.identifier),
                'definition_id': self.convert_value(self.definition_id),
                'definition': self.definition.to_dict(complete, inflated),
                'value': value,
                'created_at': self.convert_value(self.created_at),
                'modified_on': self.convert_value(self.modified_on),
                'creator_group': creator,
                'modifier_group': modifier,
                'properties': self.properties.to_dict()
                }

    def populate(self, json):
        definition_id = json.get('definition_id', None)
        if definition_id:
            self.definition_id = definition_id
            definition = json.get('definition', None)
            if definition:
                definitin_instance = ReferenceDefinition()
                definitin_instance.populate(definition)
                self.definition = definitin_instance
        if self.definition_id and self.definition:
            if self.definition.identifier and self.definition_id != self.definition.identifier:
                raise ValueException(u'Reference definitions cannot be updated')
        self.value = json.get('value', None)
        self.identifier = json.get('identifier', None)
        self.properties.populate(json.get('properties', None))
        creator_group = json.get('creator_group', None)
        if creator_group:
            cg_instance = Group()
            cg_instance.populate(creator_group)
            self.creator_group = cg_instance
        modifier_group = json.get('modifier_group', None)
        if modifier_group:
            cg_instance = Group()
            cg_instance.populate(modifier_group)
            self.modifier = cg_instance
        created_at = json.get('created_at', None)
        if created_at:
            self.created_at = strings.stringToDateTime(created_at)
        modified_on = json.get('modified_on', None)
        if modified_on:
            self.modified_on = strings.stringToDateTime(modified_on)


class Report(ExtendedLogingInformations):

    def __init__(self):
        ExtendedLogingInformations.__init__(self)
        self.properties = Properties('0')
        self.references = list()
        self.related_reports = list()
        self.title = None
        self.description = None
        self.short_description = None

    def to_dict(self, complete=True, inflated=False):
        references = list()
        related_reports = list()
        for reference in self.references:
            references.append(reference.to_dict(complete, inflated))
        references_count = len(self.references)

        if inflated:
            for related_report in self.related_reports:
                related_reports.append(related_report.to_dict(complete, inflated))

        related_count = len(self.related_reports)

        creator = None
        if self.creator_group:
            creator = self.creator_group.to_dict(False, False)
        modifier = None
        if self.modifier:
            modifier = self.modifier.to_dict(False, False)

        if complete:
            return {'identifier': self.convert_value(self.identifier),
                    'title': self.convert_value(self.title),
                    'description': self.convert_value(self.description),
                    'short_description': self.convert_value(self.short_description),
                    'references': references,
                    'references_count': references_count,
                    'properties': self.properties.to_dict(),
                    'related_reports': related_reports,
                    'related_reports_count': related_count,
                    'creator_group': creator,
                    'modifier_group': modifier,
                    }
        else:
            return {'identifier': self.identifier,
                    'title': self.title
                    }

    def populate(self, json):
        self.title = json.get('title', None)
        self.description = json.get('description', None)
        self.properties.populate(json.get('properties', None))
        self.short_description = json.get('short_description', None)
        self.identifier = json.get('identifier', None)
        self.properties.populate(json.get('properties', None))
        creator_group = json.get('creator_group', None)
        if creator_group:
            cg_instance = Group()
            cg_instance.populate(creator_group)
            self.creator_group = cg_instance
        modifier_group = json.get('modifier_group', None)
        if modifier_group:
            cg_instance = Group()
            cg_instance.populate(modifier_group)
            self.modifier = cg_instance
        created_at = json.get('created_at', None)
        if created_at:
            self.created_at = strings.stringToDateTime(created_at)
        modified_on = json.get('modified_on', None)
        if modified_on:
            self.modified_on = strings.stringToDateTime(modified_on)
        references = json.get('references', None)
        if references:
            for reference in references:
                ref = Reference()
                ref.populate(reference)
                self.references.append(ref)


class ReferenceFile(RestBase):

    def __init__(self, filename, b64encoded_data):
        self.filename = filename
        self.data = b64encoded_data

    def to_dict(self, complete=True, inflated=False):
        return {'filename': self.filename,
                'data': self.data}
