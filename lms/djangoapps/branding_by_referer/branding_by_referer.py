"""
Set user logo and other visual elements according to referrer
"""
import collections
import copy
import json
from datetime import datetime, timedelta

import edx_oauth2_provider
from crum import get_current_request
from django.conf import settings
from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin
from django.utils.six import iteritems
from django.utils.six.moves.urllib.parse import urlparse
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from openedx.core.djangoapps.user_api.models import UserPreference


class SetBrandingByReferer(MiddlewareMixin):
    """
    If the referrer is valid (meaning that exists in
    site_configuration) we used its configurations on current_theme_match
    and we store the referer on cookie/UserPreference for any future requests.
    """
    MARKETING_SITE_REFERER = 'MARKETING_SITE_REFERER'
    COOKIE_MARKETING_SITE_REFERER = 'COOKIE_MARKETING_SITE_REFERER'

    def process_request(self, request):
        """
        Process request middleware method.

        Always set the cookie value if the http_referer is in the BRANDING_BY_REFERER options.
        """
        if not self.check_feature_enable():
            return None

        self.pending_cookie = None
        options_dict = configuration_helpers.get_value('THEME_OPTIONS', {'default': True})
        referer_domain = urlparse(request.META.get('HTTP_REFERER', '')).netloc
        branding_overrides = options_dict.get('BRANDING_BY_REFERER', {}).get(referer_domain, None)
        request.branding_by_referer = {}

        if branding_overrides:
            self.pending_cookie = referer_domain
            self.get_stored_referer_data(request)
        else:
            referer_domain = None
            stored_referer_data = self.get_stored_referer_data(request)
            if stored_referer_data:
                is_valid = stored_referer_data['site_domain'] == request.get_host()
                referer_domain = stored_referer_data['referer_domain'] if is_valid else None
                branding_overrides = options_dict.get('BRANDING_BY_REFERER', {}).get(referer_domain, None)
            else:
                referer_domain = request.COOKIES.get(self.COOKIE_MARKETING_SITE_REFERER, None)
                branding_overrides = options_dict.get('BRANDING_BY_REFERER', {}).get(referer_domain, None)

        request.branding_by_referer['user_referer'] = referer_domain
        request.branding_by_referer['current_theme_match'] = branding_overrides or {}

    def get_stored_referer_data(self, request):
        """
        Method that check if the user preference is present, then updates its value depending on
        cookie value and returns the updated user preference value.

        If the user preference is not present, checks if the cookie exist and then, create a new
        user preference with the cookie value.

        If the cookie value is not set and the user preference is, set a new cookie with the value of
        the user preference.

        If either user preference or cookie are not present returns None as well if the user is not
        is not authenticated.
        """
        if request.user.is_authenticated():
            stored_referer_data = UserPreference.get_value(request.user, self.MARKETING_SITE_REFERER)
            referer_on_cookie = request.COOKIES.get(self.COOKIE_MARKETING_SITE_REFERER, None)

            if stored_referer_data and referer_on_cookie:
                try:
                    stored_referer_data_json = json.loads(stored_referer_data)
                    stored_referer_data_json['referer_domain'] = referer_on_cookie
                except ValueError:
                    # This is for support legacy user preferences records,
                    # that have a string value instead of json value.
                    stored_referer_data_json = {
                        'referer_domain': referer_on_cookie,
                        'site_domain': request.get_host()
                    }

                return self.update_user_referer_data(request, stored_referer_data_json)
            if referer_on_cookie:
                stored_referer_data = {
                    'referer_domain': referer_on_cookie,
                    'site_domain': request.get_host()
                }
                return self.update_user_referer_data(request, stored_referer_data)
            if stored_referer_data:
                stored_referer_data_json = json.loads(stored_referer_data)
                self.pending_cookie = stored_referer_data_json['referer_domain']
                return stored_referer_data_json
        return None

    def update_user_referer_data(self, request, data):
        """
        Method to update or create a UserPreference object.

        Takes the request and data to create/update the new UserPreference.

        The data format is:
            {
                "referer_domain": domain-where-it-comes-from,
                "site_domain": the-current-site-domain
            }
        """
        preference_referer_data = UserPreference.objects.update_or_create(
            user=request.user,
            key=self.MARKETING_SITE_REFERER,
            defaults={
                'value': json.dumps(data)
            }
        )
        return json.loads(preference_referer_data[0].value)

    def process_response(self, request, response):
        """
        Process response middleware method.
        """
        if not self.check_feature_enable():
            return response

        if self.pending_cookie:
            self.set_cookie(response, self.pending_cookie)
            self.pending_cookie = None

        current_branding_by_referer = getattr(request, 'branding_by_referer', {})

        if current_branding_by_referer.get('user_referer', None):
            # Logic edx-platform/common/djangoapps/student/views/login.py
            oauth_client_ids = request.session.get(edx_oauth2_provider.constants.AUTHORIZED_CLIENTS_SESSION_KEY, [])
            user_referer = '//{}'.format(current_branding_by_referer.get('user_referer'))
            referer_path = urlparse(request.META.get('HTTP_REFERER', '')).path
            url_resolver_name = getattr(request.resolver_match, 'url_name', None)

            if referer_path == '/logout':
                if request.user.is_authenticated():
                    stored_referer_data = UserPreference.get_value(request.user, self.MARKETING_SITE_REFERER)
                    if stored_referer_data:
                        stored_referer_data_json = json.loads(stored_referer_data)
                        self.set_cookie(response, stored_referer_data_json['referer_domain'])
                return redirect(user_referer)

            if url_resolver_name == 'logout' and not oauth_client_ids:
                if response.has_header('Location'):
                    response['Location'] = user_referer

        return response

    def set_cookie(self, response, cookie_value):
        """
        Method to set a new cookie with the passed value.
        """
        max_age = 30 * 24 * 60 * 60
        expires = datetime.strftime(datetime.utcnow() + timedelta(seconds=max_age), "%a, %d-%b-%Y %H:%M:%S GMT")
        response.set_cookie(
            key=self.COOKIE_MARKETING_SITE_REFERER,
            value=cookie_value,
            max_age=max_age,
            expires=expires,
            domain=settings.SESSION_COOKIE_DOMAIN,
            secure=settings.SESSION_COOKIE_SECURE or None
        )

    def check_feature_enable(self):
        """
        Check if the ENABLE_BRANDING_BY_REFERER is set and return its value.
        """
        return configuration_helpers.get_value('FEATURES', {}).get('ENABLE_BRANDING_BY_REFERER', False)


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
