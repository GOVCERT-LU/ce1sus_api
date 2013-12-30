# -*- coding: utf-8 -*-

"""module providing authentication"""

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'

import json
import requests
from ce1sus.api.restclasses import RestClass, populateClassNamebyDict, \
                                   mapResponseToObject, getData, \
                                   mapJSONToObject


def json_pretty_print(j):
  return json.dumps(j, sort_keys=True, indent=4, separators=(',', ': '))


class Ce1susAPIException(Exception):

  def __init__(self, message):
    Exception.__init__(self, message)


class Ce1susForbiddenException(Ce1susAPIException):

  def __init__(self, message):
    Ce1susAPIException.__init__(self, message)


class Ce1susNothingFoundException(Ce1susAPIException):

  def __init__(self, message):
    Ce1susAPIException.__init__(self, message)


class Ce1susUndefinedException(Ce1susAPIException):

  def __init__(self, message):
    Ce1susAPIException.__init__(self, message)


class Ce1susInvalidParameter(Ce1susAPIException):

  def __init__(self, message):
    Ce1susAPIException.__init__(self, message)


class NothingFoundException(Ce1susAPIException):

  def __init__(self, message):
    Ce1susAPIException.__init__(self, message)


class Ce1susAPIConnectionException(Ce1susAPIException):

  def __init__(self, message):
    Ce1susAPIException.__init__(self, message)


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

  @staticmethod
  def raiseException(errorMessage):
    if ':' in errorMessage:
      temp = errorMessage.split(':')
      errorClass = temp[0].strip()
      message = temp[1].strip()
      if errorClass == 'NothingFoundException':
        raise Ce1susNothingFoundException(message)
      elif errorClass == 'InvalidParameter':
        raise Ce1susInvalidParameter(message)
      else:
        raise Ce1susUndefinedException(errorMessage)
    else:
      raise Ce1susAPIException(errorMessage)

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
                               data=json.dumps(data),
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
        except requests.exceptions.HTTPError as e:
          if '403' in e.message or 'Forbidden' in e.message:
            raise Ce1susForbiddenException('Not authorized.')
          if '500' in e.message:
            raise Ce1susAPIException('Server Error'.format(e.message))
          raise Ce1susAPIException('Error ({0})'.format(e))
    except requests.ConnectionError as e:
      raise Ce1susAPIConnectionException('{0}'.format(e.message))
    # Process custom exceptions
    jsonObj = json.loads(response)
    resonseObj = jsonObj.get('response', None)
    if resonseObj:
      if resonseObj.get('status', 'ERROR') == 'ERROR':
        errorMsg = ''
        for error in resonseObj.get('errors', list()):
          for value in error.itervalues():
            errorMsg += value + '.'
        Ce1susAPI.raiseException(errorMsg)
      else:
        return jsonObj
    raise Ce1susAPIException('Undefined Error')

  def getEventByUUID(self, uuid, withDefinition=False):
    if withDefinition:
      headers = {'fulldefinitions': True}
    else:
      headers = {'fulldefinitions': False}

    result = self.__request('/event/{0}'.format(uuid),
                            None, headers)
    return mapResponseToObject(result)

  def insertEvent(self, event, withDefinition=False):
    if withDefinition:
      headers = {'fulldefinitions': True}
    else:
      headers = {'fulldefinitions': False}
    if isinstance(event, RestClass):
      data = dict(event.toJSON(True, True))
      result = self.__request('/event', data, headers)
      return mapResponseToObject(result)
    else:
      raise Ce1susAPIException(('Event does not implement '
                                + 'RestClass').format(event))

  def getEvents(self,
                startDate=None,
                endDate=None,
                offset=0,
                limit=20,
                withDefinition=False,
                uuids=list()):
    if withDefinition:
      headers = {'fulldefinitions': True}
    else:
      headers = {'fulldefinitions': False}
    headers['uuids'] = uuids
    if startDate:
      headers['startdate'] = startDate
    if endDate:
      headers['enddate'] = endDate
    if offset >= 0:
      headers['page'] = offset
    if limit:
      headers['limit'] = limit

    result = self.__request('/events', None, headers)
    key, values = getData(result)
    del key
    result = list()
    for value in values:
      result.append(mapJSONToObject(value))
    return result

  def searchEventsUUID(self,
                   objectType,
                   objectContainsAttribute=list(),
                   startDate=None,
                   endDate=None,
                   offset=0,
                   limit=20,
                   withDefinition=False):
    if withDefinition:
      headers = {'fulldefinitions': True}
    else:
      headers = {'fulldefinitions': False}

    if startDate:
      headers['startdate'] = startDate
    if endDate:
      headers['enddate'] = endDate
    if offset >= 0:
      headers['page'] = offset
    if limit:
      headers['limit'] = limit
    headers['objectattributes'] = objectContainsAttribute
    headers['objecttype'] = objectType
    result = self.__request('/search/events', None, headers)
    key, uuids = getData(result)
    del key
    return uuids

  def searchAttributes(self,
                       objectType=None,
                       objectContainsAttribute=list(),
                       filterAttributes=list(),
                       startDate=None,
                       endDate=None,
                       offset=0,
                       limit=20,
                       withDefinition=False):
    if withDefinition:
      headers = {'fulldefinitions': True}
    else:
      headers = {'fulldefinitions': False}
    if startDate:
      headers['startdate'] = startDate
    if endDate:
      headers['enddate'] = endDate
    if offset >= 0:
      headers['page'] = offset
    if limit:
      headers['limit'] = limit
    headers['objectattributes'] = objectContainsAttribute
    headers['objecttype'] = objectType
    headers['attributes'] = filterAttributes
    events = list()
    result = self.__request('/search/attributes', None, headers)
    key, values = getData(result)
    for item in values:
      jsonObject = json.loads(item)
      for key, value in jsonObject.iteritems():
        restEvent = populateClassNamebyDict(key, value, True)
        events.append(restEvent)
    return events

  def getAttributeDefinitions(self, chksums=list(), withDefinition=False):
    if withDefinition:
      headers = {'fulldefinitions': True}
    else:
      headers = {'fulldefinitions': False}
    headers['chksum'] = chksums

    result = self.__request('/definitions/attributes'.format(chksums),
                            None, headers)
    return mapResponseToObject(result)

  def getObjectDefinitions(self, chksums=list(), withDefinition=False):
    if withDefinition:
      headers = {'fulldefinitions': True}
    else:
      headers = {'fulldefinitions': False}
    headers['chksum'] = chksums

    result = self.__request('/definitions/objects'.format(chksums),
                            None, headers)
    return mapResponseToObject(result)

  def insertAttributeDefinition(self, definition, withDefinition=False):
    if withDefinition:
      headers = {'fulldefinitions': True}
    else:
      headers = {'fulldefinitions': False}
    if isinstance(definition, RestClass):
      data = dict(definition.toJSON(True, True))
      result = self.__request('/definition/attribute', data, headers)
      return mapResponseToObject(result)
    else:
      raise Ce1susAPIException(('Attribute definition does not implement '
                                + 'RestClass').format(definition))

  def insertObjectDefinition(self, definition, withDefinition=False):
    if withDefinition:
      headers = {'fulldefinitions': True}
    else:
      headers = {'fulldefinitions': False}
    if isinstance(definition, RestClass):
      data = dict(definition.toJSON(True, True))
      result = self.__request('/definition/object', data, headers)
      return mapResponseToObject(result)
    else:
      raise Ce1susAPIException(('Object definition does not implement '
                                + 'RestClass').format(definition))
