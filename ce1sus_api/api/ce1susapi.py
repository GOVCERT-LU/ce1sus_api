# -*- coding: utf-8 -*-

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'

import os
import json
import requests
from ce1sus_api.api.exceptions import Ce1susAPIException, \
                                  Ce1susForbiddenException, \
                                  Ce1susNothingFoundException, \
                                  Ce1susUndefinedException, \
                                  Ce1susUnkownDefinition, \
                                  Ce1susInvalidParameter, \
                                  Ce1susAPIConnectionException
from ce1sus_api.api.common import JSONConverter, JSONException
from ce1sus_api.api.restclasses import RestClass
from ce1sus_api.api.dictconverter import DictConverter, DictConversionException
from types import DictType


def json_pretty_print(j):
  return json.dumps(j, sort_keys=True, indent=4, separators=(',', ': '))


class Ce1susAPI(object):

  def __init__(self,
               apiUrl,
               apiKey,
               proxies=dict(),
               verify_ssl=False,
               ssl_cert=False):
    self.apiUrl = apiUrl
    self.apiKey = apiKey
    self.proxies = proxies
    self.verify_ssl = verify_ssl
    self.ssl_cert = ssl_cert
    self.definitions = None
    self.json_converter = JSONConverter(None)
    self.dictconverter = DictConverter(None)

  @staticmethod
  def raiseException(errorMessage):
    if isinstance(errorMessage, DictType):
        errorMessage = errorMessage.get('RestException', 'Fooo')

    if ':' in errorMessage:
      temp = errorMessage.split(':')
      errorClass = temp[0].strip()
      message = temp[1].strip()
    else:
      raise Ce1susAPIException(errorMessage)

    if errorClass == 'NothingFoundException':
      raise Ce1susNothingFoundException(message)
    elif errorClass == 'InvalidParameter':
      raise Ce1susInvalidParameter(message)
    elif errorClass == 'UnknownDefinitionException':
      raise Ce1susUnkownDefinition(message)
    else:
      raise Ce1susUndefinedException(errorMessage)

  def __request(self, method, data=None, extra_headers=None):
    try:
      url = '{0}/{1}'.format(self.apiUrl, method)
      headers = {'Content-Type': 'application/json; charset=utf-8',
                 'key': self.apiKey}

      if extra_headers:
        for key, value in extra_headers.items():
          headers[key] = value
      if data:
        request = requests.post(url,
                               data=self.json_converter.generate_json(data),
                               headers=headers,
                               proxies=self.proxies,
                               verify=self.verify_ssl,
                               cert=self.ssl_cert)
      else:
        request = requests.get(url,
                               headers=headers,
                               proxies=self.proxies,
                               verify=self.verify_ssl,
                               cert=self.ssl_cert)
      if request.status_code == requests.codes.ok:
        response = request.text
      else:
        try:
          request.raise_for_status()
        except requests.exceptions.HTTPError as error:
          if '403' in error.message or 'Forbidden' in error.message:
            raise Ce1susForbiddenException('Not authorized.')
          if '500' in error.message:
            raise Ce1susAPIException('Server Error'.format(error.message))
          raise Ce1susAPIException('Error ({0})'.format(error))
    except JSONException as error:
      raise Ce1susAPIException(error)
    except requests.ConnectionError as error:
      raise Ce1susAPIConnectionException('{0}'.format(error.message))

    # process answer
    try:
      rest_obj = self.json_converter.get_rest_object(response)
      return rest_obj
    except JSONException as error:
      Ce1susAPI.raiseException(error.message)

    raise Ce1susAPIException('Undefined Error')

  def get_event_by_uuid(self, uuid, withDefinition=False):
    headers = {'fulldefinitions': withDefinition}

    rest_event = self.__request('/event/{0}'.format(uuid),
                            None, headers)
    return rest_event

  def insert_event(self, event, withDefinition=False, mkrelations=True):
    headers = {'fulldefinitions': withDefinition, 'mkrelations': mkrelations}

    if isinstance(event, RestClass):
      try:
        data = self.dictconverter.convert_to_dict(event)
      except DictConversionException as error:
        raise Ce1susAPIException(error)
      rest_event = self.__request('/event', data, headers)
      return rest_event
    else:
      raise Ce1susAPIException(('Event does not implement '
                                + 'RestClass').format(event))

  def get_events(self,
                startDate=None,
                endDate=None,
                offset=0,
                limit=20,
                withDefinition=False,
                uuids=list()):
    headers = {'fulldefinitions': withDefinition,
               'uuids': uuids
               }

    if startDate:
      headers['startdate'] = startDate
    if endDate:
      headers['enddate'] = endDate
    if offset >= 0:
      headers['page'] = offset
    if limit:
      headers['limit'] = limit

    return self.__request('/events', None, headers)

  def get_attribute_definitions(self, chksums=list(), withDefinition=False):
    headers = {'fulldefinitions': withDefinition,
               'chksum': chksums
               }

    reat_att_def = self.__request('/definitions/attributes'.format(chksums),
                            None, headers)
    return reat_att_def

  def get_object_definitions(self, chksums=list(), withDefinition=False):
    headers = {'fulldefinitions': withDefinition,
               'chksum': chksums
               }

    reat_obj_def = self.__request('/definitions/objects'.format(chksums),
                            None, headers)
    return reat_obj_def

  def search_events_uuid(self,
                   objectType,
                   objectContainsAttribute=list(),
                   startDate=None,
                   endDate=None,
                   offset=0,
                   limit=20):
    headers = {'attributes': objectContainsAttribute,
               'objecttype': objectType,
               }

    if startDate:
      headers['startdate'] = startDate
    if endDate:
      headers['enddate'] = endDate
    if offset >= 0:
      headers['page'] = offset
    if limit:
      headers['limit'] = limit
    result = self.__request('/search/events', None, headers)
    return result

  def search_attributes(self,
                       objectType=None,
                       objectContainsAttribute=list(),
                       filterAttributes=list(),
                       startDate=None,
                       endDate=None,
                       offset=0,
                       limit=20,
                       withDefinition=False):
    headers = {'fulldefinitions': withDefinition,
               'attributes': objectContainsAttribute,
               'objecttype': objectType,
               'objectattributes': filterAttributes,
               }

    if startDate:
      headers['startdate'] = startDate
    if endDate:
      headers['enddate'] = endDate
    if offset >= 0:
      headers['page'] = offset
    if limit:
      headers['limit'] = limit
    result = self.__request('/search/attributes', None, headers)
    return result

  def insert_attribute_definition(self, definition, withDefinition=False):
    headers = {'fulldefinitions': withDefinition}

    if isinstance(definition, RestClass):
      data = dict(definition.to_dict())
      reat_obj_def = self.__request('/definition/attribute', data, headers)
      return reat_obj_def
    else:
      raise Ce1susAPIException(('Attribute definition does not implement '
                                + 'RestClass').format(definition))

  def insert_object_definition(self, definition, withDefinition=False):
    headers = {'fulldefinitions': withDefinition}
    if isinstance(definition, RestClass):
      data = dict(definition.to_dict())
      rest_obj_def = self.__request('/definition/object', data, headers)
      return rest_obj_def
    else:
      raise Ce1susAPIException(('Object definition does not implement '
                                + 'RestClass').format(definition))

  def load_definitions(self, cache=True, definitions_file=None):
    ret = {}

    if cache and definitions_file is None:
      raise Ce1susAPIException('If you want to cache the definitions, you need to specify a valid cache-file path')

    if cache and not definitions_file is None and os.path.isfile(definitions_file):
      with open(definitions_file, 'rb') as f:
        defs_json = f.read()

      defs_dict = json.loads(defs_json)

      for d in defs_dict:
        for v in d.values():
          ret[v['name']] = v
    else:
      defs = self.get_attribute_definitions(withDefinition=True)
      defs_dict = []
      for d in defs:
        v = d.to_dict()
        defs_dict.append(v)
        ret[v['RestAttributeDefinition']['name']] = v['RestAttributeDefinition']

      if cache:
        defs_json = json.dumps(defs_dict)

        with open(definitions_file, 'wb') as f:
          f.write(defs_json)

    self.definitions = ret

  def definition_to_chksum(self, definition):
    if self.definitions is None:
      raise Ce1susAPIException('Definitions not loaded')

    return self.definitions[definition]['chksum']
