# -*- coding: utf-8 -*-

"""
(Description)

Created on May 6, 2015
"""


__author__ = 'Weber Jean-Paul'
__email__ = 'jean-paul.weber@govcert.etat.lu'
__copyright__ = 'Copyright 2013-2014, GOVCERT Luxembourg'
__license__ = 'GPL v3+'


def get_flat_objects(obj):
    result = list()
    if obj.related_objects:
        for rel_obj in obj.related_objects:
            result = result + get_flat_objects(rel_obj.object)
    obj.related_objects = None
    result.append(obj)
    return result


def get_objects(observable):
    result = list()
    if observable.object:
        result = result + get_flat_objects(observable.object)
    if observable.observable_composition:
        for obs in observable.observable_composition.observables:
            result = result + get_objects(obs)
    if observable.related_observables:
        for rel_obs in observable.related_observables:
            result = result + get_objects(rel_obs.observable)
    return result


def extract_event_objects(event):
    result = list()
    for observable in event.observables:
        result = result + get_objects(observable)
    for indicator in event.indicators:
        for observable in indicator.observables:
            result = result + get_objects(observable)
    return result
