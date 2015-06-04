# -*- coding: utf-8 -*-

"""
(Description)

Created on Oct 16, 2014
"""
from ce1sus.api.classes.base import RestBase
from ce1sus.helpers.bitdecoder import BitBase


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


class GroupRights(BitBase):
  """
  The __bit_value is defined as follows:
  [0] : User is privileged
  [1] : User can validate
  [2] : User can set group via rest inserts
  """

  DOWNLOAD = 0
  TLP_PROPAGATION = 1

  @property
  def can_download(self):
    return self._get_value(GroupRights.DOWNLOAD)

  @can_download.setter
  def can_download(self, value):
    self._set_value(GroupRights.DOWNLOAD, value)

  @property
  def propagate_tlp(self):
    return self._get_value(GroupRights.TLP_PROPAGATION)

  @propagate_tlp.setter
  def propagate_tlp(self, value):
    self._set_value(GroupRights.TLP_PROPAGATION, value)

  def to_dict(self):
    return {'downloadfiles': self.can_download,
            'propagate_tlp': self.propagate_tlp}

  def populate(self, json):
    self.can_download = json.get('downloadfiles', False)
    self.propagate_tlp = json.get('propagate_tlp', False)


class EventPermissions(BitBase):

  ADD = 0
  MODIFY = 1
  DELETE = 2
  VALIDATE = 3
  PROPOSE = 4
  SET_GROUPS = 5
  VIEW_SHARE = 6

  @property
  def can_view(self):
    return True

  @property
  def can_view_non_shared(self):
    # TODO: implement non shared to see
    # Note this is for non shared elements
    return self._get_value(EventPermissions.VIEW_SHARE)

  @can_view_non_shared.setter
  def can_view_non_shared(self, value):
    # Note this is for non shared elements
    self._set_value(EventPermissions.VIEW_SHARE, value)

  @property
  def can_propose(self):
    return self._get_value(EventPermissions.PROPOSE)

  @can_propose.setter
  def can_propose(self, value):
    # Note if you can propose, you can see
    self._set_value(EventPermissions.PROPOSE, value)

  @property
  def can_add(self):
    return self._get_value(EventPermissions.ADD)

  @can_add.setter
  def can_add(self, value):
    # if you can add you can see
    self._set_value(EventPermissions.ADD, value)

  @property
  def can_modify(self):
    return self._get_value(EventPermissions.MODIFY)

  @can_modify.setter
  def can_modify(self, value):
    # if you can modify you can see
    self._set_value(EventPermissions.MODIFY, value)

  @property
  def can_delete(self):
    return self._get_value(EventPermissions.DELETE)

  @can_delete.setter
  def can_delete(self, value):
    # if you can delete you can see
    self._set_value(EventPermissions.DELETE, value)

  @property
  def can_validate(self):
    return self._get_value(EventPermissions.VALIDATE)

  @can_validate.setter
  def can_validate(self, value):
    # if you can validate you can see
    self._set_value(EventPermissions.VALIDATE, value)

  @property
  def set_groups(self):
    return self._get_value(EventPermissions.SET_GROUPS)

  @set_groups.setter
  def set_groups(self, value):
    # if you can validate you can see
    self._set_value(EventPermissions.SET_GROUPS, value)

  def set_all(self):
    self.can_add = True
    self.can_modify = True
    self.can_delete = True
    self.can_propose = True
    self.can_validate = True
    self.set_groups = True

  def set_default(self):
    self.can_propose = True

  def to_dict(self):
    return {'add': self.can_add,
            'modify': self.can_modify,
            'validate': self.can_validate,
            'propose': self.can_propose,
            'delete': self.can_delete,
            'set_groups': self.set_groups
            }

  def populate(self, json):
    self.can_add = json.get('add', False)
    self.can_modify = json.get('modify', False)
    self.can_validate = json.get('validate', False)
    self.can_propose = json.get('propose', False)
    self.can_delete = json.get('delete', False)
    self.set_groups = json.get('set_groups', False)


class Group(RestBase):

  def __init__(self):
    RestBase.__init__(self)
    self.name = None
    self.description = None
    self.email = None
    self.permissions = GroupRights('0')
    self.default_permissions = EventPermissions('0')
    self.gpg_key = None

  def to_dict(self, complete=True, inflated=False):
    if complete:
      return {'identifier': self.convert_value(self.identifier),
              'name': self.convert_value(self.name),
              'description': self.convert_value(self.description),
              'email': self.convert_value(self.email),
              'gpg_key': self.convert_value(self.gpg_key),
              'children': dict(),
              }
    else:
      return {'identifier': self.identifier,
              'name': self.name
              }

  def populate(self, json):
    self.identifier = json.get('identifier', None)
    self.name = json.get('name', None)
    self.description = json.get('description', None)
    self.email = json.get('email', None)
    self.gpg_key = json.get('gpg_key', None)
    # permissions setting
    self.permissions.populate(json.get('permissions', {}))
    self.default_permissions.populate(json.get('default_event_permissions', {}))
    # TODO add group
