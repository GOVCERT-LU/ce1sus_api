# -*- coding: utf-8 -*-

"""
(Description)

Created on Feb 4, 2015
"""
from ce1sus.api.classes.attribute import Attribute, Condition
from ce1sus.api.classes.definitions import AttributeDefinition, ObjectDefinition
from ce1sus.api.classes.event import Event
from ce1sus.api.classes.indicator import IndicatorType
from ce1sus.api.classes.object import Object
from ce1sus.api.classes.observables import Observable
from ce1sus.api.classes.report import ReferenceDefinition, Report, Reference
from ce1sus.api.classes.searchresult import SearchResult
import json
import requests
from requests.sessions import session
from ce1sus.api.classes.group import Group


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class Ce1susAPIException(Exception):
  """
  Base Exception for API Exceptions
  """
  pass


class UnkownMethodException(Ce1susAPIException):
  pass


class Ce1susForbiddenException(Ce1susAPIException):
  pass


class Ce1susAPIConnectionException(Ce1susAPIException):
  pass


class Ce1susNothingFoundException(Ce1susAPIException):
  """ Ce1susNothingFoundException """
  pass


class Ce1susAPI(object):

  def __init__(self,
               apiUrl,
               apiKey,
               proxies=None,
               verify_ssl=False,
               ssl_cert=None):
    if proxies is None:
      proxies = {}
    self.apiUrl = '{0}/REST/0.3.0'.format(apiUrl)
    self.apiKey = apiKey
    self.proxies = proxies
    self.verify_ssl = verify_ssl
    self.ssl_cert = ssl_cert
    self.session = session()

  def __extract_message(self, error):
    reason = error.message
    message = error.response.text
    code = error.response.status_code
    """<p>An event with uuid "54f63b0f-0c98-4e74-ab95-60c718689696" already exists</p>"""
    try:
      pos = message.index('<p>') + 3
      message = message[pos:]
      pos = message.index('</p>')
      message = message[:pos]
    except ValueError:
      # In case the message is not parsable
      pass
    return code, reason, message

  def __handle_exception(self, request):
    try:
      request.raise_for_status()
    except requests.exceptions.HTTPError as error:
      code, reason, message = self.__extract_message(error)
      message = u'{0} ({1})'.format(reason, message)
      if code == 403:
        raise Ce1susForbiddenException(message)
      elif code == 404:
        raise Ce1susNothingFoundException(message)
      else:
        raise Ce1susAPIException(message)

  def __request(self, path, method, clazz, data=None, extra_headers=None):
    try:
      url = '{0}/{1}'.format(self.apiUrl, path)
      headers = {'Content-Type': 'application/json; charset=utf-8',
                 'User-Agent': 'Ce1sus API client 0.11',
                 'key': self.apiKey}
      if extra_headers:
        for key, value in extra_headers.items():
          headers[key] = value

      if method == 'GET':
        request = self.session.get(url,
                                   headers=headers,
                                   proxies=self.proxies,
                                   verify=self.verify_ssl,
                                   cert=self.ssl_cert,
                                   cookies=self.session.cookies)
      elif method == 'PUT':
        request = self.session.put(url,
                                   json.dumps(data),
                                   headers=headers,
                                   proxies=self.proxies,
                                   verify=self.verify_ssl,
                                   cert=self.ssl_cert,
                                   cookies=self.session.cookies)
      elif method == 'DELETE':
        request = self.session.delete(url,
                                      headers=headers,
                                      proxies=self.proxies,
                                      verify=self.verify_ssl,
                                      cert=self.ssl_cert,
                                      cookies=self.session.cookies)
      elif method == 'POST':
        request = self.session.post(url,
                                    json.dumps(data),
                                    headers=headers,
                                    proxies=self.proxies,
                                    verify=self.verify_ssl,
                                    cert=self.ssl_cert,
                                    cookies=self.session.cookies)
      else:
        raise UnkownMethodException(u'Mehtod {0} is not specified can only be GET,POST,PUT or DELETE')

      if request.status_code == requests.codes.ok:
        if clazz:
          dictionary = json.loads(request.text)
          if isinstance(dictionary, list):
            result = list()
            for item in dictionary:
              instance = clazz()
              instance.populate(item)
              result.append(instance)
            return result
          else:
            instance = clazz()
            instance.populate(dictionary)
            return instance
        else:
          return request.text
      else:
        self.__handle_exception(request)
    except requests.exceptions.RequestException as error:
      raise Ce1susAPIException(error)
    except requests.ConnectionError as error:
      raise Ce1susAPIConnectionException('{0}'.format(error.message))

  def __set_complete_inflated(self, url, complete=False, inflated=False):
    if complete and not inflated:
      url = '{0}?complete=true'.format(url)
    if not complete and inflated:
      url = '{0}?inflated=true'.format(url)
    if complete and inflated:
      url = '{0}?complete=true&inflated=true'.format(url)
    return url

  def get_event_by_uuid(self, uuid, complete=False, inflated=False):
    url = '/event/{0}'.format(uuid)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_event = self.__request(url,
                                'GET',
                                Event)
    return rest_event

  def get_group_by_uuid(self, uuid, complete=False, inflated=False):
    url = '/group/{0}'.format(uuid)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_group = self.__request(url,
                                'GET',
                                Group)
    return rest_group

  def get_report_by_uuid(self, uuid, complete=False, inflated=False):
    url = '/report/{0}'.format(uuid)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_report = self.__request(url,
                                 'GET',
                                 Report)
    return rest_report

  def get_observable_by_uuid(self, uuid, complete=False, inflated=False):
    url = '/observable/{0}'.format(uuid)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_observable = self.__request(url,
                                     'GET',
                                     Observable)
    return rest_observable

  def get_object_by_uuid(self, uuid, complete=False, inflated=False):
    url = '/object/{0}'.format(uuid)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_object = self.__request(url,
                                 'GET',
                                 Object)
    return rest_object

  def get_attribute_by_uuid(self, object_uuid, attribute_uuid, complete=False, inflated=False):
    url = '/object/{0}/attribute/{1}'.format(object_uuid, attribute_uuid)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_object = self.__request(url,
                                 'GET',
                                 Attribute)
    return rest_object

  def delete_event_by_uuid(self, uuid):
    url = '/event/{0}'.format(uuid)
    rest_event = self.__request(url,
                                'DELETE',
                                None,
                                None)
    return rest_event

  def delete_object_by_uuid(self, uuid):
    url = '/object/{0}'.format(uuid)
    rest_event = self.__request(url,
                                'DELETE',
                                None,
                                None)
    return rest_event

  def delete_attribute_by_uuid(self, object_uuid, attribue_uuid):
    url = '/object/{0}/attribute/{1}'.format(object_uuid, attribue_uuid)
    rest_event = self.__request(url,
                                'DELETE',
                                None,
                                None)
    return rest_event

  def delete_observable_by_uuid(self, uuid):
    url = '/observable/{0}'.format(uuid)
    rest_event = self.__request(url,
                                'DELETE',
                                None,
                                None)
    return rest_event

  def insert_event(self, event, complete=False, inflated=False):
    url = '/event'
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_event = self.__request(url,
                                'POST',
                                Event,
                                data=event.to_dict(True, True))
    return rest_event

  def insert_observable(self, observable, complete=False, inflated=False):
    if not observable.event_id:
      raise Ce1susAPIException(u'Cannot insert observable as event_id is not set')

    url = '/event/{0}/observable'.format(observable.event_id)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_event = self.__request(url,
                                'POST',
                                Observable,
                                data=observable.to_dict(True, True))
    return rest_event

  def insert_object(self, obj, complete=False, inflated=False):
    if not obj.observable_id:
      raise Ce1susAPIException(u'Cannot insert observable as event_id is not set')
    url = '/observable/{0}/object'.format(obj.observable_id)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_event = self.__request(url,
                                'POST',
                                Object,
                                data=obj.to_dict(True, True))
    return rest_event

  def insert_attribute(self, attribute, complete=False, inflated=False):
    if not attribute.object_id:
      raise Ce1susAPIException(u'Cannot insert observable as event_id is not set')
    url = '/object/{0}/attribute'.format(attribute.object_id)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_event = self.__request(url,
                                'POST',
                                Object,
                                data=attribute.to_dict(True, True))
    return rest_event

  def insert_reference(self, reference, complete=False, inflated=False):
    if not reference.report_id:
      raise Ce1susAPIException(u'Cannot insert reference as report_id is not set')
    url = '/report/{0}/reference'.format(reference.report_id)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_event = self.__request(url,
                                'POST',
                                Reference,
                                data=reference.to_dict(True, True))
    return rest_event

  def insert_report(self, report, complete=False, inflated=False):
    if not report.event_id:
      raise Ce1susAPIException(u'Cannot insert observable as event_id is not set')

    url = '/event/{0}/report'.format(report.event_id)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_event = self.__request(url,
                                'POST',
                                Report,
                                data=report.to_dict(True, True))
    return rest_event

  def login(self):
    text = self.__request('/login',
                          'POST',
                          None,
                          None
                          )
    return json.loads(text)

  def logout(self):
    text = self.__request('/logout',
                          'GET',
                          None
                          )
    if text == 'User logged out':
      return True
    else:
      return False

  def __get_search_attributes(self):
    text = self.__request('/search/attributes?complete=true',
                          'GET',
                          None
                          )
    return json.loads(text)

  def get_attribute_definitions(self, complete=False, inflated=False):
    url = '/attributedefinition'
    url = self.__set_complete_inflated(url, complete, inflated)
    definitions = self.__request(url,
                                 'GET',
                                 AttributeDefinition
                                 )
    return definitions

  def get_reference_definitions(self, complete=False, inflated=False):
    url = '/referencedefinition'
    url = self.__set_complete_inflated(url, complete, inflated)
    definitions = self.__request(url,
                                 'GET',
                                 ReferenceDefinition
                                 )
    return definitions

  def get_indicator_types(self, complete=False, inflated=False):
    url = '/indicatortypes'
    url = self.__set_complete_inflated(url, complete, inflated)
    definitions = self.__request(url,
                                 'GET',
                                 IndicatorType
                                 )
    return definitions

  def get_conditions(self, complete=False, inflated=False):
    url = '/condition'
    url = self.__set_complete_inflated(url, complete, inflated)
    definitions = self.__request(url,
                                 'GET',
                                 Condition
                                 )
    return definitions

  def get_object_definitions(self, complete=False, inflated=False):
    url = '/objectdefinition'
    url = self.__set_complete_inflated(url, complete, inflated)
    definitions = self.__request(url,
                                 'GET',
                                 ObjectDefinition
                                 )
    return definitions

  def __get_attribute_id(self, attribute_name, is_report=False):
    # cover the special cases
    if attribute_name in ['uuid', 'title', 'description', 'Any']:
      return attribute_name
    fields = self.__get_search_attributes()
    identifier = None
    for field in fields:
      field_name = field['name']
      if is_report:
        if attribute_name in field_name and 'report' in field_name:
          identifier = field['identifier']
          identifier = identifier.split(':')
          identifier = identifier[1]
          break
      else:
        if attribute_name in field_name:
          identifier = field['identifier']
          break
    if identifier:
      return identifier

  def search_attributes(self, operator, attribute_name, value, is_in_report=False):
    """ Will never throw a Nothing found Exception """
    if operator not in ['==', '<=', '<', '>', '>=', 'like']:
      raise Ce1susAPIException('"{0}" is not a valid operator'.format(operator))
    field = None
    if attribute_name:
      # get the definition id for the attribute
      field = self.__get_attribute_id(attribute_name, is_in_report)

    data = {'operator': operator, 'field': field, 'value': value}
    text = self.__request('/search', 'POST', None, data)
    items = json.loads(text)
    result = list()
    for item in items:
      result_item = SearchResult()
      result_item.populate(item)
      result.append(result_item)
    return result

  def get_unvalidated_events(self, count=10, page=1):
    url = "/validate/unvalidated?count={0}&page={1}&sorting%5Bcreated_at%5D=desc".format(count, page)
    events_json = self.__request(url,
                                 'GET',
                                 None
                                 )
    event_dict = json.loads(events_json)
    events_dict = event_dict.get('data', list())
    result = list()

    for event_dict in events_dict:
      event = Event()
      event.populate(event_dict)
      result.append(event)

    return result

  def validate_event(self, event):
    url = "event/{0}/validate".format(event.identifier)
    events_json = self.__request(url,
                                 'PUT',
                                 None
                                 )
    if events_json:
      return True
    else:
      return False
