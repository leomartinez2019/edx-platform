"""
Set user logo and other visual elements according to referrer
"""
import collections
import copy
from crum import get_current_request

from django.utils.six import iteritems

from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers


def get_branding_referer_url_for_current_user():
    """ get valid referer url saved for this user """
    current_branding_by_referer = getattr(get_current_request(), 'branding_by_referer', {})
    if not current_branding_by_referer.get('user_referer', None):
        return None
    return '//{}'.format(current_branding_by_referer['user_referer'])


def update(target, data):
    """ recursive dict.update """
    for key, value in iteritems(data):
        if isinstance(value, collections.Mapping):
            target[key] = update(target.get(key, {}), value)
        else:
            target[key] = value
    return target


def get_options_with_overrides_for_current_user():
    """
    Helper method to access current overrides dict (e.g. {"logo_src":"example.jpg"})
    """
    options_dict = copy.deepcopy(configuration_helpers.get_value('THEME_OPTIONS', {}))
    current_branding_by_referer = getattr(get_current_request(), 'branding_by_referer', {})
    if not current_branding_by_referer.get('user_referer', None):
        return options_dict
    overrides = copy.deepcopy(current_branding_by_referer['current_theme_match'])
    return update(options_dict, overrides)
