"""
Overwites some site configuration according to the referer
"""
import copy
import json
import edx_oauth2_provider
from datetime import datetime, timedelta

from django.conf import settings
from django.utils.deprecation import MiddlewareMixin
from django.utils.six import iteritems
from django.utils.six.moves.urllib.parse import urlparse
from django.shortcuts import redirect

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
    DEFAULT_REFERERS = []

    def process_request(self, request):
        """
        Process request middleware method.

        Always set the cookie value if the http_referer is in the BRANDING_BY_REFERER options.
        """
        if not self.check_feature_enable():
            return None

        self.pending_cookie = None
        options_dict = configuration_helpers.get_value('THEME_OPTIONS', {'default': True})
        self.DEFAULT_REFERERS = options_dict.get('DEFAULT_REFERERS', [])
        referer_domain = urlparse(request.META.get('HTTP_REFERER', '')).netloc
        branding_overrides = options_dict.get('BRANDING_BY_REFERER', {}).get(referer_domain, None)
        request.branding_by_referer = {}

        if branding_overrides:
            # Get the current cookie
            referer_on_cookie = request.COOKIES.get(self.COOKIE_MARKETING_SITE_REFERER, None)
            if not referer_on_cookie:
                # Just set the cookie if it's not present
                self.pending_cookie = referer_domain
            elif referer_domain not in self.DEFAULT_REFERERS:
                # Overwrite the existing cookie only if the HTTP referer is not a default referer
                self.pending_cookie = referer_domain
            else:
                # In this case, the referer_domain is a default referer and the cookie is set, so
                # set the referer_domain to the cookie value. Also get the right branding overrides
                referer_domain = referer_on_cookie
                branding_overrides = options_dict.get('BRANDING_BY_REFERER', {}).get(referer_domain, None)
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
        if not request.user.is_authenticated():
            return None

        stored_referer_data = UserPreference.get_value(request.user, self.MARKETING_SITE_REFERER)
        referer_on_cookie = request.COOKIES.get(self.COOKIE_MARKETING_SITE_REFERER, None)

        if stored_referer_data and referer_on_cookie:
            try:
                stored_referer_data_json = json.loads(stored_referer_data)
                # If, for some reason, the cookie and the db preference are different, give preference
                # to the db value if this is not a default referer and the cookie is a default referer
                if (
                    referer_on_cookie in self.DEFAULT_REFERERS and
                    stored_referer_data_json['referer_domain'] not in self.DEFAULT_REFERERS
                ):
                    self.pending_cookie = stored_referer_data_json['referer_domain']
                    return stored_referer_data_json

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


class SetConfigurationByReferer(MiddlewareMixin):
    """
    This middleware checks if the current logged-in user has a marketing site referer preference.
    If so, it overwrites some values of the site configuration based on the referer.
    It depends on the SetBrandingByReferer middleware to apply the configuration overwrites, as that
    middleware sets the referer preference for the current logged-in user. Therefore this middleware
    must be located below the SetBrandingByReferer one in the MIDDLEWARE_CLASSES setting
    """
    MARKETING_SITE_REFERER = 'MARKETING_SITE_REFERER'
    OVERRIDE_MKTG_REFERER_KEY = 'CURRENT_OVERRIDE_REFERER'
    CONFIGURATION_BY_REFERER_KEY = 'CONFIGURATION_BY_REFERER'

    def process_request(self, request):
        """
        Process request middleware method.
        """
        self.validate_reset_configuration(request)

        if not self.is_feature_enabled():
            return None

        referer_domain_preference = self.get_stored_referer_preference(request)
        if not referer_domain_preference:
            return None

        # Just return if the site configuration is not enabled
        if not configuration_helpers.is_site_configuration_enabled():
            return None

        # Get current referer configuration
        current_referer_configuration = self._get_referer_configurations(referer_domain_preference)
        # Don't bother on continuing if no configurations for the current referer
        if not current_referer_configuration:
            return None

        # Save a copy of the original SiteConfiguration dict
        request.original_site_conf = copy.deepcopy(
            configuration_helpers.get_current_site_configuration().values
        )

        self._update_conf(current_referer_configuration, referer_domain_preference)

    def _get_referer_configurations(self, referer_domain):
        """
        This method extracts the override configurations for a specific referer
        """
        referers_configurations = configuration_helpers.get_value(self.CONFIGURATION_BY_REFERER_KEY)

        if not referers_configurations:
            return None

        return referers_configurations.get(
            referer_domain
        )

    def _update_conf(self, referer_conf, referer_domain):
        """
        Update the current site configuration based on the referer configuration
        """
        current_conf_values = configuration_helpers.get_current_site_configuration().values
        for key, value in iteritems(referer_conf):
            if isinstance(value, dict):
                try:
                    merged = current_conf_values.get(key, {}).copy()
                except AttributeError:
                    merged = {}
                merged.update(value)
                current_conf_values[key] = merged
                continue
            current_conf_values[key] = value

        # Adding a key to the current configuration to identify it as a overriden set
        current_conf_values[self.OVERRIDE_MKTG_REFERER_KEY] = referer_domain
        return

    def get_stored_referer_preference(self, request):
        """
        Read the referer domain value from the current logged-in user preferences
        """
        if not request.user.is_authenticated():
            return None

        stored_referer_data = UserPreference.get_value(request.user, self.MARKETING_SITE_REFERER)
        if not stored_referer_data:
            return None

        try:
            stored_referer_data_json = json.loads(stored_referer_data)
            referer_domain_preference = stored_referer_data_json['referer_domain']
        except ValueError:
            # TODO: log something
            return None

        return referer_domain_preference

    def process_response(self, request, response):
        """
        Process response middleware method.
        """
        possible_override_referer = configuration_helpers.get_value(self.OVERRIDE_MKTG_REFERER_KEY)
        # if the override referer is present, clean the configuration
        if possible_override_referer:
            current_conf = configuration_helpers.get_current_site_configuration()
            setattr(current_conf, 'values', request.original_site_conf)
            request.original_site_conf = None
        return response

    def is_feature_enabled(self):
        """
        Check if the ENABLE_BRANDING_BY_REFERER feature flag is set and return its value.
        """
        return configuration_helpers.get_value('FEATURES', {}).get('ENABLE_CONFIGURATION_BY_REFERER', False)

    def validate_reset_configuration(self, request):
        """
        As a security mesure, make sure the configuration was reset and has no overrides
        """
        possible_override_referer = configuration_helpers.get_value(self.OVERRIDE_MKTG_REFERER_KEY)
        # if this setting is present, we need to reload the current settings as they were not correctly cleaned
        # in the last request
        if not possible_override_referer:
            return

        try:
            current_conf = configuration_helpers.get_current_site_configuration()
            current_conf.refresh_from_db()
        except AttributeError:
            return
