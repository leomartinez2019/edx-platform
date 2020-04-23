"""
Utility functions used during user authentication.
"""
from urlparse import urlparse

from django.conf import settings
from django.utils import http

from openedx.core.djangoapps.site_configuration import helpers as configuration_helpers

def is_safe_login_or_logout_redirect(request, redirect_to):
    """
    Determine if the given redirect URL/path is safe for redirection.
    """
    request_host = request.get_host()  # e.g. 'courses.edx.org'

    login_redirect_whitelist = set(configuration_helpers.get_value('LOGIN_REDIRECT_WHITELIST', settings.LOGIN_REDIRECT_WHITELIST))
    login_redirect_whitelist.add(request_host)

    is_safe_url = http.is_safe_url(redirect_to, allowed_hosts=login_redirect_whitelist, require_https=True)
    if not is_safe_url:
        is_safe_url = _redirect_to_matches_wildcard(redirect_to, login_redirect_whitelist)
    return is_safe_url

def _redirect_to_matches_wildcard(redirect_to, redirect_whitelist, require_https=True):
    """
    Determine if a given domain matches with the wildcards of a given list.
    """
    url_info = urlparse(redirect_to)
    scheme = url_info.scheme

    # Consider URLs without a scheme (e.g. //example.com/p) to be http.
    if not url_info.scheme and url_info.netloc:
        scheme = 'http'

    valid_schemes = ['https'] if require_https else ['http', 'https']
    if url_info.netloc:
        url_domain = url_info.netloc
        wildcard_domain = url_domain[url_domain.find("."):]

        wildcards = {domain for domain in redirect_whitelist if domain.startswith(".")}
        return wildcard_domain in wildcards and (not scheme or scheme in valid_schemes)

    return not scheme or scheme in valid_schemes
