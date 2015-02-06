# -*- coding: utf-8 -*-

"""
(Description)

Created on Feb 4, 2015
"""
import json
import requests
from requests.sessions import Session

from ce1sus.api.classes.attribute import Attribute
from ce1sus.api.classes.event import Event
from ce1sus.api.classes.object import Object
from ce1sus.api.classes.observables import Observable


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
               proxies=dict(),
               verify_ssl=False,
               ssl_cert=False):
    self.apiUrl = '{0}/REST/0.3.0'.format(apiUrl)
    self.apiKey = apiKey
    self.proxies = proxies
    self.verify_ssl = verify_ssl
    self.ssl_cert = ssl_cert
    self.session = Session()

  def __handle_exception(self, request):
    try:
      request.raise_for_status()
    except requests.exceptions.HTTPError as error:
      if '403' in error.message or 'Forbidden' in error.message:
        raise Ce1susForbiddenException('Not authorized.')
      if '404' in error.message:
        raise Ce1susNothingFoundException('Item not found ({0})'.format(error))
      if '500' in error.message:
        raise Ce1susAPIException('Server Error {0}'.format(error.message))
      raise Ce1susAPIException('Error ({0})'.format(error))

  def __request(self, path, method, clazz, data=None, extra_headers=None):
    try:
      url = '{0}/{1}'.format(self.apiUrl, path)
      headers = {'Content-Type': 'application/json; charset=utf-8',
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
          instance = clazz()
          dictionary = json.loads(request.text)
          instance.populate(dictionary, True)

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
    print url
    return url

  def get_event_by_uuid(self, uuid, complete=False, inflated=False):
    url = '/event/{0}'.format(uuid)
    url = self.__set_complete_inflated(url, complete, inflated)
    rest_event = self.__request(url,
                                'GET',
                                Event)
    return rest_event

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

  def login(self, apikey):
    headers = dict()
    headers['key'] = apikey
    text = self.__request('/login',
                          'POST',
                          None,
                          None,
                          headers
                          )
    print text

  def logout(self):
    text = self.__request('/logout',
                          'GET',
                          None
                          )
    print text
