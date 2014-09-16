# -*- coding: utf-8 -*-

"""
(Description)

Created on Aug 1, 2014
"""

__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


P_C_RELATIONS = {'File-File': 'Dropped',
                 'File-IP': 'Connected_To',
                 'File-Domain': 'Connected_To',
                 'File-URI': 'Connected_To',
                 'EmailMessage-File': 'Contains',
                 'EmailMessage-Link': 'Contains',
                 }

RELATION_INV_RELATION = {'Created': 'Created_By',
                         'Deleted': 'Deleted_By',
                         'Modified_Properties_Of': 'Properties_Modified_By',
                         'Read_From': 'Read_From_By',
                         'Wrote_To': 'Written_To_By',
                         'Downloaded_From': 'Downloaded_To',
                         'Downloaded': 'Downloaded_By',
                         'Uploaded': 'Uploaded_By',
                         'Uploaded_To': 'Uploaded_From',
                         'Sent_Via_Upload': 'Received_Via_Upload',
                         'Suspended': 'Suspended_By',
                         'Paused': 'Paused_By',
                         'Resumed': 'Resumed_By',
                         'Opened': 'Opened_By',
                         'Closed': 'Closed_By',
                         'Copied_From': 'Copied_To',
                         'Copied': 'Copied_By',
                         'Moved_From': 'Moved_To',
                         'Moved': 'Moved_By',
                         'Searched_For': 'Searched_For_By',
                         'Allocated': 'Allocated_By',
                         'Initialized_To': 'Initialized_By',
                         'Sent': 'Sent_By/Sent_To',
                         'Received': 'Received_By/Received_From',
                         'Mapped_Into': 'Mapped_By',
                         'Properties_Queried': 'Properties_Queried_By',
                         'Values_Enumerated': 'Values_Enumerated_By',
                         'Bound': 'Bound_By',
                         'Freed': 'Freed_By',
                         'Killed': 'Killed_By',
                         'Encrypted': 'Encrypted_By',
                         'Encrypted_To': 'Encrypted_From',
                         'Decrypted': 'Decrypted_By',
                         'Packed': 'Packed_By',
                         'Unpacked': 'Unpacked_By',
                         'Packed_From': 'Packed_Into',
                         'Encoded': 'Encoded_By',
                         'Decoded': 'Decoded_By',
                         'Compressed_From': 'Compressed_Into',
                         'Compressed': 'Compressed_By',
                         'Decompressed': 'Decompressed_By',
                         'Joined': 'Joined_By',
                         'Merged': 'Merged_By',
                         'Locked': 'Locked_By',
                         'Unlocked': 'Unlocked_By',
                         'Hooked': 'Hooked_By',
                         'Unhooked': 'Unhooked_By',
                         'Monitored': 'Monitored_By',
                         'Listened_On': 'Listened_On_By',
                         'Renamed_From': 'Renamed_To',
                         'Renamed': 'Renamed_By',
                         'Injected_Into': 'Injected_As',
                         'Injected': 'Injected_By',
                         'Deleted_From': 'Previously_Contained',
                         'Loaded_Into': 'Loaded_From',
                         'Set_To': 'Set_From',
                         'Resolved_To': 'Related_To',
                         'Dropped': 'Dropped_By',
                         'Contains': 'Contained_Within',
                         'Extracted_From': 'Extracted_Of',
                         'Installed_By': 'Installed_Due',
                         'Connected_To': 'Connected_From',
                         'Sub-domain_Of': 'Supra-domain_Of',
                         'Root_Domain_Of': 'Root_Domain_Of',
                         'FQDN_Of': 'FQDN_Of',
                         'Parent_Of': 'Child_Of',
                         'Characterizes': 'Characterized_By'
                         }


def get_parent_child_relation(parent_class, child_class):
  key = u'{0}-{1}'.format(parent_class.__class__.__name__, child_class.__class__.__name__)
  relation = P_C_RELATIONS.get(key, None)
  if relation:
    return relation
  else:
    raise CyboxMapperRelationException(u'Relation for "{0}" is undefined'.format(key))


def get_inverse_relation(relation):
  inv_relation = RELATION_INV_RELATION.get(relation)
  if inv_relation:
    return inv_relation
  else:
    raise CyboxMapperRelationException(u'Invert relation for "{0}" is undefined'.format(inv_relation))


class MapperException(Exception):
  pass


class CyboxMapperException(MapperException):
  pass


class CyboxNotMappableException(CyboxMapperException):
  pass


class CyboxMapperDepricatedException(CyboxMapperException):
  pass


class CyboxMapperRelationException(CyboxMapperException):
  pass


class StixMapperException(MapperException):
  pass
