"""
Overwites some site configuration according to the referer
"""
import copy
import json

from django.utils.deprecation import MiddlewareMixin
from django.utils.six import iteritems
from django.utils.six.moves.urllib.parse import urlparse
from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers
from openedx.core.djangoapps.user_api.models import UserPreference


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

        # just return if the site configuration is not enabled
        if not configuration_helpers.is_site_configuration_enabled():
            return None

        # Save a copy of the original SiteConfiguration dict
        request.original_site_conf = copy.deepcopy(
            configuration_helpers.get_current_site_configuration().values
        )

        self._update_conf(request, referer_domain_preference)

    def _override_marketing_urls(self, referer_domain):
        """
        Method to override the mktg links of the current site configuration
        """
        mktg_urls = configuration_helpers.get_value("MKTG_URLS")
        if not mktg_urls:
            return

        for name, url in iteritems(mktg_urls):
            url_domain = urlparse(url).netloc
            if not url_domain:
                continue
            mktg_urls[name] = url.replace(url_domain, referer_domain)

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

    def _insert_referer_configurations(self, referer_domain):
        """
        This method merges the override configurations of a specific referer with the current site configuration
        """
        current_referer_configuration = self._get_referer_configurations(referer_domain)
        if not current_referer_configuration:
            return

        current_conf_values = configuration_helpers.get_current_site_configuration().values
        for key, value in iteritems(current_referer_configuration):
            if isinstance(value, dict):
                try:
                    merged = current_conf_values.get(key, {}).copy()
                except AttributeError:
                    merged = {}
                merged.update(value)
                current_conf_values[key] = merged
                continue
            current_conf_values[key] = value

        return

    def _update_conf(self, request, referer_domain):
        """
        Update the current site configuration based on the referer
        """
        # Adding a key to the current configuration to identify it as a overriden set
        current_conf = configuration_helpers.get_current_site_configuration()
        current_conf.values[self.OVERRIDE_MKTG_REFERER_KEY] = referer_domain

        self._override_marketing_urls(referer_domain)
        self._insert_referer_configurations(referer_domain)
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
